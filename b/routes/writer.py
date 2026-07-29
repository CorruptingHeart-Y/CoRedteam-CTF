from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

from routes.schema import NormalizedRoute


class WriteErrorCode(str, Enum):
    OUTPUT_FILE_EXISTS = "OUTPUT_FILE_EXISTS"
    UNSAFE_OUTPUT_PATH = "UNSAFE_OUTPUT_PATH"
    YAML_SERIALIZATION_ERROR = "YAML_SERIALIZATION_ERROR"
    WRITE_FAILED = "WRITE_FAILED"


@dataclass(frozen=True)
class WriteError:
    code: WriteErrorCode
    message: str


@dataclass(frozen=True)
class WriteResult:
    route_id: str
    output_path: Path | None = None
    yaml_preview: str | None = None
    errors: tuple[WriteError, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            self.output_path is not None
            and self.yaml_preview is not None
            and not self.errors
        )

    @property
    def error_codes(self) -> tuple[WriteErrorCode, ...]:
        return tuple(error.code for error in self.errors)


_CANONICAL_ID_PATTERN = re.compile(
    r"^[a-z0-9]+(?:[-_][a-z0-9]+)*(?::[a-z0-9]+(?:[-_][a-z0-9]+)*)*$"
)
_STABLE_PAYLOAD_REF_PATTERN = re.compile(
    r"^primitive:[A-Za-z0-9_-]+:sha256:[0-9a-f]{16}$"
)


def candidate_route_filename(canonical_id: str) -> str:
    if (
        not canonical_id
        or ".." in canonical_id
        or "/" in canonical_id
        or "\\" in canonical_id
        or not _CANONICAL_ID_PATTERN.fullmatch(canonical_id)
    ):
        raise ValueError("canonical route ID is not safe for a file name")
    return f"{canonical_id.replace(':', '-')}.yaml"


def _resolve_output_path(output_dir: Path, file_name: str) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    if any(part == ".." for part in output_dir.parts):
        raise ValueError("output directory may not contain path traversal")

    lowered_parts = tuple(part.lower() for part in output_dir.parts)
    if any(
        lowered_parts[index : index + 2] == ("templates", "builtin")
        for index in range(len(lowered_parts) - 1)
    ):
        raise ValueError("route factory may not write to templates/builtin")

    resolved_dir = output_dir.resolve(strict=False)
    resolved_path = (resolved_dir / file_name).resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_dir)
    except ValueError as exc:
        raise ValueError("output file escapes the requested output directory") from exc
    return resolved_dir, resolved_path


def render_candidate_route_yaml(route: NormalizedRoute) -> str:
    plain = route.to_plain()
    activation = plain.get("activation")
    if not isinstance(activation, dict) or activation.get("state") != "draft":
        raise ValueError("candidate route activation.state must be draft")
    if activation.get("source") != "route_factory":
        raise ValueError("candidate route activation.source must be route_factory")
    if plain.get("generation_status") != "candidate_only":
        raise ValueError("candidate route generation_status must be candidate_only")

    payload_refs = (
        plain.get("payload_template_ref"),
        plain.get("materialization", {}).get("payload_template_ref")
        if isinstance(plain.get("materialization"), dict)
        else None,
    )
    if not all(
        isinstance(value, str) and _STABLE_PAYLOAD_REF_PATTERN.fullmatch(value)
        for value in payload_refs
    ):
        raise ValueError("candidate route must contain stable payload template references")

    return yaml.safe_dump(
        plain,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


def _atomic_write_text(destination: Path, content: str, overwrite: bool) -> None:
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)

    temp_path: Path | None = None
    reserved_destination = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        if not overwrite:
            reservation = os.open(
                destination,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
            os.close(reservation)
            reserved_destination = True
        os.replace(temp_path, destination)
        temp_path = None
        reserved_destination = False
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        if reserved_destination:
            destination.unlink(missing_ok=True)


def write_candidate_route(
    route: NormalizedRoute,
    output_dir: Path,
    overwrite: bool = False,
) -> WriteResult:
    try:
        file_name = candidate_route_filename(route.canonical_id)
        resolved_dir, output_path = _resolve_output_path(output_dir, file_name)
    except (OSError, TypeError, ValueError) as exc:
        return WriteResult(
            route_id=route.canonical_id,
            errors=(WriteError(WriteErrorCode.UNSAFE_OUTPUT_PATH, str(exc)),),
        )

    try:
        yaml_preview = render_candidate_route_yaml(route)
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        return WriteResult(
            route_id=route.canonical_id,
            errors=(WriteError(WriteErrorCode.YAML_SERIALIZATION_ERROR, str(exc)),),
        )

    if output_path.exists() and not overwrite:
        return WriteResult(
            route_id=route.canonical_id,
            yaml_preview=yaml_preview,
            errors=(
                WriteError(
                    WriteErrorCode.OUTPUT_FILE_EXISTS,
                    f"output file already exists: {output_path}",
                ),
            ),
        )

    try:
        resolved_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(output_path, yaml_preview, overwrite=overwrite)
    except FileExistsError:
        return WriteResult(
            route_id=route.canonical_id,
            yaml_preview=yaml_preview,
            errors=(
                WriteError(
                    WriteErrorCode.OUTPUT_FILE_EXISTS,
                    f"output file already exists: {output_path}",
                ),
            ),
        )
    except OSError as exc:
        return WriteResult(
            route_id=route.canonical_id,
            yaml_preview=yaml_preview,
            errors=(WriteError(WriteErrorCode.WRITE_FAILED, str(exc)),),
        )

    return WriteResult(
        route_id=route.canonical_id,
        output_path=output_path,
        yaml_preview=yaml_preview,
    )
