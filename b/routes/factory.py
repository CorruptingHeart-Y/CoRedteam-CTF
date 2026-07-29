from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import yaml

from routes.normalizer import normalize_route_proposal
from routes.primitive_adapter import PrimitiveAdapter
from routes.schema import RouteProposal
from routes.writer import (
    WriteErrorCode,
    _atomic_write_text,
    _resolve_output_path,
    candidate_route_filename,
    render_candidate_route_yaml,
    write_candidate_route,
)


DUPLICATE_ROUTE_ID = "DUPLICATE_ROUTE_ID"
REPORT_FILE_NAME = "route_generation_report.json"


@dataclass(frozen=True)
class GenerationDiagnostic:
    proposal_index: int
    error_codes: tuple[str, ...]
    message: str

    def to_plain(self) -> dict[str, object]:
        return {
            "proposal_index": self.proposal_index,
            "error_codes": list(self.error_codes),
            "message": self.message,
        }


@dataclass(frozen=True)
class YamlPreview:
    canonical_id: str
    file_name: str
    yaml: str

    def to_plain(self) -> dict[str, str]:
        return {
            "canonical_id": self.canonical_id,
            "file_name": self.file_name,
            "yaml": self.yaml,
        }


@dataclass(frozen=True)
class GenerationReport:
    proposals_received: int
    normalized: int
    written: int
    candidate_only: int
    rejected: int
    duplicate_ids: tuple[str, ...]
    diagnostics: tuple[GenerationDiagnostic, ...]
    output_files: tuple[str, ...]
    dry_run: bool
    yaml_previews: tuple[YamlPreview, ...] = ()

    def to_plain(self) -> dict[str, object]:
        return {
            "proposals_received": self.proposals_received,
            "normalized": self.normalized,
            "written": self.written,
            "candidate_only": self.candidate_only,
            "rejected": self.rejected,
            "duplicate_ids": list(self.duplicate_ids),
            "diagnostics": [item.to_plain() for item in self.diagnostics],
            "output_files": list(self.output_files),
            "dry_run": self.dry_run,
            "yaml_previews": [item.to_plain() for item in self.yaml_previews],
        }


def _diagnostic(
    proposal_index: int,
    error_codes: tuple[str, ...],
    message: str,
) -> GenerationDiagnostic:
    return GenerationDiagnostic(
        proposal_index=proposal_index,
        error_codes=error_codes,
        message=message,
    )


def _build_report(
    proposals_received: int,
    normalized: int,
    written: int,
    duplicate_ids: list[str],
    diagnostics: list[GenerationDiagnostic],
    output_files: list[str],
    dry_run: bool,
    yaml_previews: list[YamlPreview],
) -> GenerationReport:
    rejected = proposals_received - normalized
    return GenerationReport(
        proposals_received=proposals_received,
        normalized=normalized,
        written=written,
        candidate_only=normalized,
        rejected=rejected,
        duplicate_ids=tuple(duplicate_ids),
        diagnostics=tuple(diagnostics),
        output_files=tuple(output_files),
        dry_run=dry_run,
        yaml_previews=tuple(yaml_previews),
    )


def generate_candidate_routes(
    proposals: Sequence[RouteProposal],
    adapter: PrimitiveAdapter,
    output_dir: Path,
    dry_run: bool = False,
    overwrite: bool = False,
) -> GenerationReport:
    proposals_received = len(proposals)
    normalized = 0
    written = 0
    duplicate_ids: list[str] = []
    diagnostics: list[GenerationDiagnostic] = []
    output_files: list[str] = []
    yaml_previews: list[YamlPreview] = []
    seen_ids: set[str] = set()

    report_path: Path | None = None
    output_path_error: tuple[str, str] | None = None
    try:
        _, report_path = _resolve_output_path(output_dir, REPORT_FILE_NAME)
        if not dry_run and report_path.exists() and not overwrite:
            output_path_error = (
                WriteErrorCode.OUTPUT_FILE_EXISTS.value,
                f"generation report already exists: {report_path}",
            )
    except (OSError, TypeError, ValueError) as exc:
        output_path_error = (WriteErrorCode.UNSAFE_OUTPUT_PATH.value, str(exc))

    for proposal_index, proposal in enumerate(proposals):
        result = normalize_route_proposal(proposal, adapter)
        if not result.ok or result.route is None:
            error_codes = tuple(error.code.value for error in result.errors)
            fields = ", ".join(error.field for error in result.errors)
            diagnostics.append(
                _diagnostic(
                    proposal_index,
                    error_codes,
                    f"route proposal normalization failed for fields: {fields}",
                )
            )
            continue

        route = result.route
        if route.canonical_id in seen_ids:
            duplicate_ids.append(route.canonical_id)
            diagnostics.append(
                _diagnostic(
                    proposal_index,
                    (DUPLICATE_ROUTE_ID,),
                    f"duplicate canonical route ID: {route.canonical_id}",
                )
            )
            continue
        seen_ids.add(route.canonical_id)

        try:
            file_name = candidate_route_filename(route.canonical_id)
        except (TypeError, ValueError) as exc:
            diagnostics.append(
                _diagnostic(
                    proposal_index,
                    (WriteErrorCode.UNSAFE_OUTPUT_PATH.value,),
                    str(exc),
                )
            )
            continue

        if output_path_error is not None:
            diagnostics.append(
                _diagnostic(
                    proposal_index,
                    (output_path_error[0],),
                    output_path_error[1],
                )
            )
            continue

        if dry_run:
            try:
                yaml_preview = render_candidate_route_yaml(route)
            except (TypeError, ValueError, yaml.YAMLError) as exc:
                diagnostics.append(
                    _diagnostic(
                        proposal_index,
                        (WriteErrorCode.YAML_SERIALIZATION_ERROR.value,),
                        str(exc),
                    )
                )
                continue
            yaml_previews.append(
                YamlPreview(
                    canonical_id=route.canonical_id,
                    file_name=file_name,
                    yaml=yaml_preview,
                )
            )
            normalized += 1
            continue

        write_result = write_candidate_route(route, output_dir, overwrite=overwrite)
        if not write_result.ok or write_result.output_path is None:
            diagnostics.append(
                _diagnostic(
                    proposal_index,
                    tuple(error.code.value for error in write_result.errors),
                    "; ".join(error.message for error in write_result.errors),
                )
            )
            continue

        output_files.append(str(write_result.output_path))
        normalized += 1
        written += 1

    report = _build_report(
        proposals_received,
        normalized,
        written,
        duplicate_ids,
        diagnostics,
        output_files,
        dry_run,
        yaml_previews,
    )
    if dry_run or report_path is None or output_path_error is not None:
        return report

    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_json = json.dumps(
            report.to_plain(),
            ensure_ascii=False,
            indent=2,
        ) + "\n"
        _atomic_write_text(report_path, report_json, overwrite=overwrite)
    except FileExistsError:
        diagnostics.append(
            _diagnostic(
                -1,
                (WriteErrorCode.OUTPUT_FILE_EXISTS.value,),
                f"generation report already exists: {report_path}",
            )
        )
        report = _build_report(
            proposals_received,
            normalized,
            written,
            duplicate_ids,
            diagnostics,
            output_files,
            dry_run,
            yaml_previews,
        )
    except OSError as exc:
        diagnostics.append(
            _diagnostic(
                -1,
                (WriteErrorCode.WRITE_FAILED.value,),
                str(exc),
            )
        )
        report = _build_report(
            proposals_received,
            normalized,
            written,
            duplicate_ids,
            diagnostics,
            output_files,
            dry_run,
            yaml_previews,
        )
    return report
