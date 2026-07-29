from __future__ import annotations

import hashlib
import json
from pathlib import Path

from routes.admission import ADMITTED_CANDIDATE, load_and_admit_candidate_route
from routes.normalizer import SSTI_CWE_ALIASES
from routes.primitive_adapter import PrimitiveAdapter
from routes.schema import (
    AdmissionDecision,
    NormalizedRoute,
    RegisteredRoute,
    RegistryDiagnostic,
    RegistryErrorCode,
    RegistryLoadResult,
    RegistryRegistrationResult,
    RouteRegistrySnapshot,
)


def route_fingerprint(route: NormalizedRoute) -> str:
    canonical_json = json.dumps(
        route.to_plain(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


def _source_path(path: Path | None) -> str | None:
    if path is None:
        return None
    return str(Path(path).resolve(strict=False))


class RouteRegistry:
    def __init__(self, adapter: PrimitiveAdapter) -> None:
        self._adapter = adapter
        self._routes: dict[str, RegisteredRoute] = {}
        self._diagnostics: list[RegistryDiagnostic] = []

    def __len__(self) -> int:
        return len(self._routes)

    def _finish_registration(
        self,
        result: RegistryRegistrationResult,
    ) -> RegistryRegistrationResult:
        self._diagnostics.extend(result.diagnostics)
        return result

    def _registration_error(
        self,
        code: RegistryErrorCode,
        source_path: str | None,
        canonical_id: str | None,
        message: str,
    ) -> RegistryRegistrationResult:
        diagnostic = RegistryDiagnostic(
            code=code,
            source_path=source_path,
            canonical_id=canonical_id,
            message=message,
        )
        return self._finish_registration(
            RegistryRegistrationResult(
                registered=False,
                duplicate=code == RegistryErrorCode.DUPLICATE_ROUTE,
                conflict=code == RegistryErrorCode.CONFLICTING_ROUTE_DEFINITION,
                registered_route=None,
                diagnostics=(diagnostic,),
            )
        )

    def register_decision(
        self,
        decision: AdmissionDecision,
        source_path: Path | None = None,
    ) -> RegistryRegistrationResult:
        normalized_source = _source_path(source_path)
        if not isinstance(decision, AdmissionDecision) or not decision.accepted:
            canonical_id = (
                decision.canonical_id
                if isinstance(decision, AdmissionDecision)
                else None
            )
            return self._registration_error(
                RegistryErrorCode.ROUTE_NOT_ADMITTED,
                normalized_source,
                canonical_id,
                "registry accepts only successful Admission decisions",
            )
        if decision.status != ADMITTED_CANDIDATE:
            return self._registration_error(
                RegistryErrorCode.INVALID_ADMISSION_STATUS,
                normalized_source,
                decision.canonical_id,
                "Admission decision status is not admitted_candidate",
            )
        if decision.route is None:
            return self._registration_error(
                RegistryErrorCode.ADMISSION_ROUTE_MISSING,
                normalized_source,
                decision.canonical_id,
                "accepted Admission decision does not contain a route",
            )

        route = decision.route
        if (
            route.activation.state != "draft"
            or route.activation.source != "route_factory"
            or route.generation_status != "candidate_only"
            or decision.canonical_id != route.canonical_id
        ):
            return self._registration_error(
                RegistryErrorCode.ROUTE_NOT_ADMITTED,
                normalized_source,
                route.canonical_id,
                "Admission decision does not contain an unchanged draft candidate",
            )

        fingerprint = route_fingerprint(route)
        existing = self._routes.get(route.canonical_id)
        if existing is not None:
            if existing.route_fingerprint == fingerprint:
                return self._registration_error(
                    RegistryErrorCode.DUPLICATE_ROUTE,
                    normalized_source,
                    route.canonical_id,
                    "identical canonical route is already registered",
                )
            return self._registration_error(
                RegistryErrorCode.CONFLICTING_ROUTE_DEFINITION,
                normalized_source,
                route.canonical_id,
                "canonical route ID has a different registered definition",
            )

        registered_route = RegisteredRoute(
            canonical_id=route.canonical_id,
            route=route,
            source_path=normalized_source,
            route_fingerprint=fingerprint,
        )
        self._routes[route.canonical_id] = registered_route
        return RegistryRegistrationResult(
            registered=True,
            duplicate=False,
            conflict=False,
            registered_route=registered_route,
            diagnostics=(),
        )

    def _directory_error(
        self,
        code: RegistryErrorCode,
        source_path: str,
        message: str,
    ) -> RegistryLoadResult:
        diagnostic = RegistryDiagnostic(
            code=code,
            source_path=source_path,
            canonical_id=None,
            message=message,
        )
        self._diagnostics.append(diagnostic)
        return RegistryLoadResult(
            files_discovered=0,
            files_admitted=0,
            routes_registered=0,
            rejected=0,
            duplicates=0,
            conflicts=0,
            diagnostics=(diagnostic,),
        )

    def load_directory(self, directory: Path) -> RegistryLoadResult:
        requested = Path(directory)
        try:
            requested_source = str(requested.resolve(strict=False))
            exists = requested.exists()
            is_directory = requested.is_dir() if exists else False
        except OSError:
            return self._directory_error(
                RegistryErrorCode.UNSAFE_REGISTRY_PATH,
                str(requested),
                "candidate route directory could not be safely resolved",
            )
        if not exists:
            return self._directory_error(
                RegistryErrorCode.REGISTRY_DIRECTORY_NOT_FOUND,
                requested_source,
                "candidate route directory does not exist",
            )
        if not is_directory:
            return self._directory_error(
                RegistryErrorCode.REGISTRY_PATH_NOT_DIRECTORY,
                requested_source,
                "candidate route path is not a directory",
            )

        try:
            base = requested.resolve(strict=True)
            entries = sorted(
                (
                    path
                    for path in requested.iterdir()
                    if path.suffix.lower() in {".yaml", ".yml"}
                ),
                key=lambda path: (str(path.resolve(strict=False)).casefold(), str(path)),
            )
        except OSError:
            return self._directory_error(
                RegistryErrorCode.UNSAFE_REGISTRY_PATH,
                requested_source,
                "candidate route directory could not be safely enumerated",
            )

        files_admitted = 0
        routes_registered = 0
        rejected = 0
        duplicates = 0
        conflicts = 0
        diagnostics: list[RegistryDiagnostic] = []

        for candidate in entries:
            candidate_source = str(candidate.resolve(strict=False))
            try:
                resolved_candidate = candidate.resolve(strict=True)
                safe_file = resolved_candidate.is_relative_to(base) and resolved_candidate.is_file()
            except OSError:
                safe_file = False
            if not safe_file:
                diagnostic = RegistryDiagnostic(
                    code=RegistryErrorCode.UNSAFE_REGISTRY_PATH,
                    source_path=candidate_source,
                    canonical_id=None,
                    message="candidate YAML resolves outside the registry directory or is not a file",
                )
                diagnostics.append(diagnostic)
                self._diagnostics.append(diagnostic)
                rejected += 1
                continue

            decision = load_and_admit_candidate_route(resolved_candidate, self._adapter)
            if not decision.accepted:
                rejected += 1
                rejection_diagnostics = tuple(
                    RegistryDiagnostic(
                        code=RegistryErrorCode.REGISTRY_FILE_REJECTED,
                        source_path=str(resolved_candidate),
                        canonical_id=decision.canonical_id,
                        message=item.message,
                        admission_code=item.code,
                    )
                    for item in decision.diagnostics
                ) or (
                    RegistryDiagnostic(
                        code=RegistryErrorCode.REGISTRY_FILE_REJECTED,
                        source_path=str(resolved_candidate),
                        canonical_id=decision.canonical_id,
                        message="candidate YAML was rejected by Route Admission",
                    ),
                )
                diagnostics.extend(rejection_diagnostics)
                self._diagnostics.extend(rejection_diagnostics)
                continue

            files_admitted += 1
            registration = self.register_decision(decision, resolved_candidate)
            diagnostics.extend(registration.diagnostics)
            routes_registered += int(registration.registered)
            duplicates += int(registration.duplicate)
            conflicts += int(registration.conflict)

        return RegistryLoadResult(
            files_discovered=len(entries),
            files_admitted=files_admitted,
            routes_registered=routes_registered,
            rejected=rejected,
            duplicates=duplicates,
            conflicts=conflicts,
            diagnostics=tuple(diagnostics),
        )

    def get(self, canonical_id: str) -> RegisteredRoute | None:
        return self._routes.get(canonical_id)

    def list_all(self) -> tuple[RegisteredRoute, ...]:
        return tuple(self._routes[key] for key in sorted(self._routes))

    def query(
        self,
        cwe_id: str | None = None,
        current_state: str | None = None,
        target_primitive: str | None = None,
        technique: str | None = None,
    ) -> tuple[RegisteredRoute, ...]:
        canonical_cwe: str | None = None
        if cwe_id is not None:
            canonical_cwe = SSTI_CWE_ALIASES.get(cwe_id.strip().upper())
            if canonical_cwe is None:
                return ()

        return tuple(
            registered
            for registered in self.list_all()
            if (canonical_cwe is None or registered.route.cwe_id == canonical_cwe)
            and (current_state is None or registered.route.current_state == current_state)
            and (
                target_primitive is None
                or registered.route.target_primitive == target_primitive
            )
            and (technique is None or registered.route.technique == technique)
        )

    def snapshot(self) -> RouteRegistrySnapshot:
        return RouteRegistrySnapshot(
            routes=self.list_all(),
            diagnostics=tuple(self._diagnostics),
        )
