from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse

from .audit_ledger import AuditLedger
from .calibration import DEFAULT_CALIBRATION_PRESET, calibration_preset_names, get_calibration_preset
from .controlled_adapter import AdapterExportBundle, ControlIntent, ControlPlan, ControlledAdapterFramework
from .corpus import ProfileCorpus
from .fingerprints import extract_fingerprint_bundle
from .iteration import RecursiveIterationResult, RecursiveSignatureIterator
from .kernel import ChameleonKernel
from .objects import SurfaceObject
from .operators import BucketTimingOperator, NormalizeTraceShapeOperator, RedactIdentifierFieldsOperator, SortFieldsOperator
from .policy import AuthorizationManifest
from .target_profile import OperationalMask
from .transform_operator import TransformOperator
from .adapters.network_adapter import NetworkAdapter, NetworkAdapterConfig, NetworkRequest, NetworkTransport
from .adapters.trace_adapter import TraceAdapter


GUI_SCOPE = (
    "authorized_input",
    "trace_or_network_observation",
    "target_calibration",
    "operational_mask",
    "adapter_plan",
    "explicit_export",
)


OPERATOR_FACTORIES: dict[str, Callable[[], TransformOperator]] = {
    "Normalize shape": NormalizeTraceShapeOperator,
    "Sort fields": SortFieldsOperator,
    "Bucket timing": BucketTimingOperator,
    "Redact identifiers": RedactIdentifierFieldsOperator,
}


@dataclass(frozen=True)
class GuiSnapshot:
    object_count: int
    mask_name: str | None
    plan_decision: str | None
    feedback_score: float | None
    ledger_entries: int
    iteration_stop_reason: str | None


@dataclass(frozen=True)
class TargetCalibrationResult:
    urls: tuple[str, ...]
    object_count: int
    mask_name: str


@dataclass(frozen=True)
class GuiActionState:
    import_trace: bool
    fetch_network: bool
    calibrate_target: bool
    build_mask: bool
    build_plan: bool
    run_iteration: bool
    export_plan: bool
    export_ledger: bool


class ChameleonGuiModel:
    """Small application model used by the Tkinter shell and tests."""

    def __init__(self, *, kernel: ChameleonKernel | None = None):
        self.kernel = kernel or ChameleonKernel()
        self.framework = ControlledAdapterFramework(kernel=self.kernel)
        self.iterator = RecursiveSignatureIterator(kernel=self.kernel)
        self.corpus = ProfileCorpus()
        self.ledger = AuditLedger()
        self.objects: list[SurfaceObject] = []
        self.mask: OperationalMask | None = None
        self.plan: ControlPlan | None = None
        self.bundle: AdapterExportBundle | None = None
        self.iteration_result: RecursiveIterationResult | None = None

    def snapshot(self) -> GuiSnapshot:
        return GuiSnapshot(
            object_count=len(self.objects),
            mask_name=self.mask.name if self.mask else None,
            plan_decision=self.plan.overall_decision if self.plan else None,
            feedback_score=self.plan.feedback_score if self.plan else None,
            ledger_entries=len(self.ledger.read_all()),
            iteration_stop_reason=self.iteration_result.stop_reason if self.iteration_result else None,
        )

    def action_state(
        self,
        *,
        auth_ready: bool,
        url_ready: bool,
        network_authorized: bool,
        selected_operator_count: int,
        calibration_ready: bool = False,
    ) -> GuiActionState:
        has_objects = bool(self.objects)
        has_mask = self.mask is not None
        needs_network_auth = any(obj.media_type.startswith("application/network") for obj in self.objects)
        return GuiActionState(
            import_trace=auth_ready,
            fetch_network=auth_ready and network_authorized and url_ready,
            calibrate_target=auth_ready and network_authorized and calibration_ready,
            build_mask=has_objects,
            build_plan=(
                auth_ready
                and has_objects
                and has_mask
                and selected_operator_count > 0
                and (not needs_network_auth or network_authorized)
            ),
            run_iteration=(
                auth_ready
                and has_objects
                and has_mask
                and selected_operator_count > 0
                and (not needs_network_auth or network_authorized)
            ),
            export_plan=self.plan is not None,
            export_ledger=bool(self.ledger.read_all()),
        )

    def clear(self) -> None:
        self.objects.clear()
        self.mask = None
        self.plan = None
        self.bundle = None
        self.iteration_result = None
        self.ledger = AuditLedger()

    def calibration_preset_names(self) -> tuple[str, ...]:
        return calibration_preset_names()

    def build_authorization(
        self,
        *,
        source_name: str,
        owner_or_controller: str,
        permission_basis: str,
        evidence_ref: str | None = None,
        allow_network: bool = False,
    ) -> AuthorizationManifest:
        allowed_uses = ["offline_analysis", "offline_redaction", "adapter_operation"]
        if allow_network:
            allowed_uses.append("network_observation")
        return AuthorizationManifest(
            source_name=source_name.strip(),
            owner_or_controller=owner_or_controller.strip(),
            permission_basis=permission_basis.strip(),
            allowed_uses=tuple(allowed_uses),
            evidence_ref=evidence_ref.strip() or None if evidence_ref else None,
        )

    def import_trace_file(self, path: str | Path, authorization: AuthorizationManifest) -> list[SurfaceObject]:
        adapter = TraceAdapter(authorization)
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            objects = adapter.from_jsonl_file(path)
        elif suffix == ".csv":
            objects = adapter.from_csv_file(path)
        elif suffix == ".json":
            objects = adapter.from_json_file(path)
        else:
            raise ValueError("supported trace formats are .json, .jsonl, and .csv")
        self.objects.extend(objects)
        self.plan = None
        self.bundle = None
        self.iteration_result = None
        return objects

    def import_records(
        self,
        records: list[dict[str, object]],
        authorization: AuthorizationManifest,
    ) -> list[SurfaceObject]:
        objects = TraceAdapter(authorization).from_records(records)
        self.objects.extend(objects)
        self.plan = None
        self.bundle = None
        self.iteration_result = None
        return objects

    def fetch_network_observation(
        self,
        *,
        url: str,
        authorization: AuthorizationManifest,
        allowed_hosts: tuple[str, ...] = (),
        include_body: bool = False,
        transport: NetworkTransport | None = None,
    ) -> SurfaceObject:
        url = url.strip()
        if not url:
            raise ValueError("url is required")
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        hosts = tuple(h.strip().lower() for h in allowed_hosts if h.strip()) or ((host,) if host else ())
        adapter = NetworkAdapter(
            authorization,
            config=NetworkAdapterConfig(allowed_hosts=hosts, include_body=include_body),
            transport=transport,
        )
        obj = adapter.fetch(NetworkRequest(url))
        self.objects.append(obj)
        self.plan = None
        self.bundle = None
        self.iteration_result = None
        return obj

    def calibrate_target(
        self,
        *,
        base_url: str,
        paths: tuple[str, ...] | list[str],
        authorization: AuthorizationManifest,
        mask_name: str,
        version: str = "1.0.0",
        global_tolerance: float | None = None,
        calibration_preset: str = DEFAULT_CALIBRATION_PRESET,
        include_body: bool = False,
        transport: NetworkTransport | None = None,
    ) -> TargetCalibrationResult:
        urls = self._calibration_urls(base_url=base_url, paths=paths)
        parsed = urlparse(urls[0])
        host = (parsed.hostname or "").lower()
        adapter = NetworkAdapter(
            authorization,
            config=NetworkAdapterConfig(allowed_hosts=(host,), include_body=include_body),
            transport=transport,
        )
        objects = [adapter.fetch(NetworkRequest(url)) for url in urls]
        self.objects = list(objects)
        self.mask = None
        self.plan = None
        self.bundle = None
        self.iteration_result = None
        mask = self.build_mask(
            name=mask_name or host,
            version=version,
            global_tolerance=global_tolerance,
            calibration_preset=calibration_preset,
        )
        return TargetCalibrationResult(urls=urls, object_count=len(objects), mask_name=mask.name)

    def build_mask(
        self,
        *,
        name: str,
        version: str = "1.0.0",
        global_tolerance: float | None = None,
        calibration_preset: str = DEFAULT_CALIBRATION_PRESET,
    ) -> OperationalMask:
        if not self.objects:
            raise ValueError("at least one observation is required")
        preset = get_calibration_preset(calibration_preset)
        normalized = [NormalizeTraceShapeOperator().apply(obj).transformed for obj in self.objects]
        signatures = [self.kernel.signature_for(obj) for obj in normalized]
        self.corpus = ProfileCorpus()
        profile = self.corpus.build_profile(
            name=name.strip() or "gui_mask",
            version=version.strip() or "1.0.0",
            signatures=signatures,
            tags=("gui", "operational", preset.name),
            notes=preset.notes,
        )
        self.mask = profile.to_operational_mask(
            global_tolerance=global_tolerance if global_tolerance is not None else preset.global_tolerance,
            dimension_tolerances=preset.dimension_tolerances,
            residue_externalization_surfaces=preset.residue_externalization_surfaces,
        )
        self.plan = None
        self.bundle = None
        self.iteration_result = None
        return self.mask

    def build_plan(
        self,
        *,
        authorization: AuthorizationManifest,
        objective: str,
        operator_names: tuple[str, ...],
    ) -> ControlPlan:
        if not self.objects:
            raise ValueError("at least one observation is required")
        if self.mask is None:
            raise ValueError("an operational mask is required")
        operators = tuple(self._operator_for(name) for name in operator_names)
        if not operators:
            raise ValueError("at least one operator is required")
        intent = ControlIntent(
            objective=objective.strip() or "authorized adapter operation",
            target_profile_name=self.mask.name,
            mode="adapter_operation",
            requested_network_io=any(obj.media_type.startswith("application/network") for obj in self.objects),
            export_level="operational_plan",
            capabilities=("network_observation",),
        )
        self.plan = self.framework.build_plan(
            intent=intent,
            objects=self.objects,
            operators=operators,
            target=self.mask,
            authorization=authorization,
        )
        self.bundle = self.framework.export_bundle(self.plan)
        self.ledger.append(self.plan)
        return self.plan

    def run_iteration(
        self,
        *,
        authorization: AuthorizationManifest,
        operator_names: tuple[str, ...],
        max_rounds: int = 3,
        min_improvement: float = 0.000001,
    ) -> RecursiveIterationResult:
        if not self.objects:
            raise ValueError("at least one observation is required")
        if self.mask is None:
            raise ValueError("an operational mask is required")
        operators = tuple(self._operator_for(name) for name in operator_names)
        if not operators:
            raise ValueError("at least one operator is required")
        self.iteration_result = self.iterator.run(
            objects=self.objects,
            operators=operators,
            target=self.mask,
            authorization=authorization,
            mode="adapter_operation",
            max_rounds=max_rounds,
            min_improvement=min_improvement,
        )
        self.ledger.append(self.iteration_result)
        return self.iteration_result

    def export_plan(self, path: str | Path) -> Path:
        if self.bundle is None:
            raise ValueError("no plan is available")
        return self.bundle.write_json(path)

    def export_ledger(self, path: str | Path) -> Path:
        return self.ledger.write_jsonl(path)

    def plan_summary(self) -> str:
        if self.plan is None:
            return "No plan has been built yet."
        payload = {
            "decision": self.plan.overall_decision,
            "feedback_score": self.plan.feedback_score,
            "decision_counts": self.plan.decision_counts(),
            "steps": len(self.plan.steps),
            "target": self.plan.target_name,
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def iteration_summary(self) -> str:
        if self.iteration_result is None:
            return "No recursive iteration has been run yet."
        payload = {
            "iteration_id": self.iteration_result.iteration_id,
            "target": self.iteration_result.target_name,
            "rounds": len(self.iteration_result.rounds),
            "converged": self.iteration_result.converged,
            "stop_reason": self.iteration_result.stop_reason,
            "final_average_distance": self.iteration_result.final_average_distance,
            "selected_operator_counts": self.iteration_result.selected_operator_counts(),
            "top_drift_dimensions": self.iteration_result.top_drift_dimensions(),
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def fingerprint_summary(self, *, limit: int = 3) -> dict[str, object]:
        objects = self.objects[:limit]
        bundles = [extract_fingerprint_bundle(obj) for obj in objects]
        layers = sorted({fingerprint.layer for bundle in bundles for fingerprint in bundle.fingerprints})
        coverage = [bundle.coverage() for bundle in bundles]
        return {
            "objects_summarized": len(objects),
            "available_layers": layers,
            "coverage": [
                {
                    "layer_count": item.layer_count,
                    "missing_layers": item.missing_layers,
                    "bundle_digest": item.bundle_digest,
                }
                for item in coverage
            ],
            "bundle_digests": [bundle.digest for bundle in bundles],
            "layer_specs": bundles[0].explain() if bundles else {},
        }

    def _operator_for(self, name: str) -> TransformOperator:
        try:
            return OPERATOR_FACTORIES[name]()
        except KeyError as exc:
            raise ValueError(f"unknown operator: {name}") from exc

    def _calibration_urls(self, *, base_url: str, paths: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        base_url = base_url.strip()
        if not base_url:
            raise ValueError("calibration base URL is required")
        parsed_base = urlparse(base_url)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            raise ValueError("calibration base URL must be http or https")
        base_context = base_url if base_url.endswith("/") else f"{base_url}/"
        base_host = (parsed_base.hostname or "").lower()
        raw_paths = [path.strip() for path in paths if path.strip()]
        if not raw_paths:
            raw_paths = [parsed_base.path or "/"]

        urls: list[str] = []
        seen: set[str] = set()
        for raw_path in raw_paths:
            candidate = raw_path if urlparse(raw_path).scheme else urljoin(base_context, raw_path)
            parsed_candidate = urlparse(candidate)
            if parsed_candidate.scheme != parsed_base.scheme or (parsed_candidate.hostname or "").lower() != base_host:
                raise ValueError("calibration paths must stay within the base host")
            if candidate not in seen:
                urls.append(candidate)
                seen.add(candidate)
        if not urls:
            raise ValueError("at least one calibration URL is required")
        return tuple(urls)


def main() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    class ChameleonTkApp(tk.Tk):
        def __init__(self) -> None:
            super().__init__()
            self.title("Chameleon Adapter Workbench")
            self.geometry("980x720")
            self.minsize(900, 640)
            self.model = ChameleonGuiModel()
            self.operator_vars: dict[str, tk.BooleanVar] = {}
            self._build_vars()
            self._build_ui(ttk, filedialog, messagebox, scrolledtext)
            self._bind_state_vars()
            self._wire_state()

        def _build_vars(self) -> None:
            self.source_var = tk.StringVar(value="local-workbench")
            self.owner_var = tk.StringVar(value="operator")
            self.permission_var = tk.StringVar(value="authorized adapter work")
            self.evidence_var = tk.StringVar()
            self.network_auth_var = tk.BooleanVar(value=True)
            self.calibration_base_var = tk.StringVar()
            self.url_var = tk.StringVar()
            self.allowed_host_var = tk.StringVar()
            self.include_body_var = tk.BooleanVar(value=False)
            self.preset_var = tk.StringVar(value=DEFAULT_CALIBRATION_PRESET)
            self.mask_name_var = tk.StringVar(value="workbench_mask")
            self.version_var = tk.StringVar(value="1.0.0")
            self.tolerance_var = tk.DoubleVar(value=0.70)
            self.objective_var = tk.StringVar(value="authorized adapter operation")
            for index, name in enumerate(OPERATOR_FACTORIES):
                self.operator_vars[name] = tk.BooleanVar(value=index < 2)

        def _build_ui(self, ttk, filedialog, messagebox, scrolledtext) -> None:
            self._filedialog = filedialog
            self._messagebox = messagebox
            root = ttk.Frame(self, padding=12)
            root.pack(fill="both", expand=True)
            root.columnconfigure(0, weight=1)
            root.columnconfigure(1, weight=1)
            root.rowconfigure(3, weight=1)

            auth = ttk.LabelFrame(root, text="Authorization", padding=10)
            auth.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
            for col in range(4):
                auth.columnconfigure(col, weight=1)
            self._entry(auth, "Source", self.source_var, 0, 0)
            self._entry(auth, "Owner", self.owner_var, 0, 1)
            self._entry(auth, "Basis", self.permission_var, 0, 2)
            self._entry(auth, "Evidence", self.evidence_var, 0, 3)
            ttk.Checkbutton(auth, text="Network observation", variable=self.network_auth_var, command=self._wire_state).grid(
                row=2, column=0, sticky="w", pady=(8, 0)
            )

            ingest = ttk.LabelFrame(root, text="Observations", padding=10)
            ingest.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(0, 8))
            ingest.columnconfigure(1, weight=1)
            self.load_button = ttk.Button(ingest, text="Import trace file", command=self._import_trace)
            self.load_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))
            ttk.Label(ingest, text="JSON / JSONL / CSV").grid(row=0, column=1, sticky="w")
            ttk.Label(ingest, text="Calibration base").grid(row=1, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(ingest, textvariable=self.calibration_base_var).grid(row=1, column=1, sticky="ew", pady=(10, 0))
            ttk.Label(ingest, text="Calibration paths").grid(row=2, column=0, sticky="nw", pady=(8, 0))
            self.calibration_paths = tk.Text(ingest, height=4, width=24, wrap="none")
            self.calibration_paths.grid(row=2, column=1, sticky="ew", pady=(8, 0))
            self.calibration_paths.insert("1.0", "/\n")
            self.calibration_paths.bind("<<Modified>>", self._paths_modified)
            self.calibrate_button = ttk.Button(ingest, text="Calibrate target", command=self._calibrate_target)
            self.calibrate_button.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
            ttk.Separator(ingest).grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
            ttk.Label(ingest, text="URL").grid(row=5, column=0, sticky="w")
            ttk.Entry(ingest, textvariable=self.url_var).grid(row=5, column=1, sticky="ew")
            ttk.Label(ingest, text="Allowed host").grid(row=6, column=0, sticky="w", pady=(8, 0))
            ttk.Entry(ingest, textvariable=self.allowed_host_var).grid(row=6, column=1, sticky="ew", pady=(8, 0))
            ttk.Checkbutton(ingest, text="Include response body", variable=self.include_body_var).grid(
                row=7, column=1, sticky="w", pady=(8, 0)
            )
            self.fetch_button = ttk.Button(ingest, text="Fetch observation", command=self._fetch_network)
            self.fetch_button.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(10, 0))

            mask = ttk.LabelFrame(root, text="Operational Mask", padding=10)
            mask.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(0, 8))
            mask.columnconfigure(1, weight=1)
            ttk.Label(mask, text="Scope").grid(row=0, column=0, sticky="w")
            self.preset_combo = ttk.Combobox(
                mask,
                textvariable=self.preset_var,
                values=self.model.calibration_preset_names(),
                state="readonly",
            )
            self.preset_combo.grid(row=0, column=1, sticky="ew")
            self.preset_combo.bind("<<ComboboxSelected>>", self._preset_changed)
            ttk.Label(mask, text="Name").grid(row=1, column=0, sticky="w", pady=(8, 0))
            ttk.Entry(mask, textvariable=self.mask_name_var).grid(row=1, column=1, sticky="ew", pady=(8, 0))
            ttk.Label(mask, text="Version").grid(row=2, column=0, sticky="w", pady=(8, 0))
            ttk.Entry(mask, textvariable=self.version_var).grid(row=2, column=1, sticky="ew", pady=(8, 0))
            ttk.Label(mask, text="Tolerance").grid(row=3, column=0, sticky="w", pady=(8, 0))
            ttk.Spinbox(mask, from_=0.05, to=3.00, increment=0.05, textvariable=self.tolerance_var).grid(
                row=3, column=1, sticky="ew", pady=(8, 0)
            )
            self.mask_button = ttk.Button(mask, text="Build mask", command=self._build_mask)
            self.mask_button.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0))

            plan = ttk.LabelFrame(root, text="Adapter Plan", padding=10)
            plan.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 8))
            plan.columnconfigure(1, weight=1)
            ttk.Label(plan, text="Objective").grid(row=0, column=0, sticky="w")
            ttk.Entry(plan, textvariable=self.objective_var).grid(row=0, column=1, sticky="ew", padx=(8, 0))
            ops = ttk.Frame(plan)
            ops.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
            for index, (name, var) in enumerate(self.operator_vars.items()):
                ttk.Checkbutton(ops, text=name, variable=var, command=self._wire_state).grid(
                    row=0, column=index, sticky="w", padx=(0, 12)
                )
            buttons = ttk.Frame(plan)
            buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
            buttons.columnconfigure((0, 1, 2, 3, 4), weight=1)
            self.plan_button = ttk.Button(buttons, text="Build plan", command=self._build_plan)
            self.plan_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
            self.iteration_button = ttk.Button(buttons, text="Run iteration", command=self._run_iteration)
            self.iteration_button.grid(row=0, column=1, sticky="ew", padx=6)
            self.export_plan_button = ttk.Button(buttons, text="Export plan", command=self._export_plan)
            self.export_plan_button.grid(row=0, column=2, sticky="ew", padx=6)
            self.export_ledger_button = ttk.Button(buttons, text="Export audit", command=self._export_ledger)
            self.export_ledger_button.grid(row=0, column=3, sticky="ew", padx=6)
            ttk.Button(buttons, text="Clear", command=self._clear).grid(row=0, column=4, sticky="ew", padx=(6, 0))

            results = ttk.LabelFrame(root, text="Status", padding=10)
            results.grid(row=3, column=0, columnspan=2, sticky="nsew")
            results.rowconfigure(0, weight=1)
            results.columnconfigure(0, weight=1)
            self.output = scrolledtext.ScrolledText(results, height=14, wrap="word")
            self.output.grid(row=0, column=0, sticky="nsew")
            self._set_output("Ready.")

        def _entry(self, parent, label: str, variable, row: int, column: int) -> None:
            ttk.Label(parent, text=label).grid(row=row, column=column, sticky="w", padx=(0, 8))
            ttk.Entry(parent, textvariable=variable).grid(row=row + 1, column=column, sticky="ew", padx=(0, 8))

        def _bind_state_vars(self) -> None:
            for variable in (
                self.source_var,
                self.owner_var,
                self.permission_var,
                self.calibration_base_var,
                self.url_var,
                self.mask_name_var,
                self.objective_var,
            ):
                variable.trace_add("write", lambda *_: self._wire_state())

        def _paths_modified(self, _event=None) -> None:
            self.calibration_paths.edit_modified(False)
            self._wire_state()

        def _preset_changed(self, _event=None) -> None:
            preset = get_calibration_preset(self.preset_var.get())
            self.tolerance_var.set(preset.global_tolerance)
            self._wire_state()

        def _authorization(self) -> AuthorizationManifest:
            return self.model.build_authorization(
                source_name=self.source_var.get(),
                owner_or_controller=self.owner_var.get(),
                permission_basis=self.permission_var.get(),
                evidence_ref=self.evidence_var.get(),
                allow_network=self.network_auth_var.get(),
            )

        def _selected_operators(self) -> tuple[str, ...]:
            return tuple(name for name, var in self.operator_vars.items() if var.get())

        def _import_trace(self) -> None:
            path = self._filedialog.askopenfilename(
                title="Import trace file",
                filetypes=(("Trace files", "*.json *.jsonl *.csv"), ("All files", "*.*")),
            )
            if not path:
                return
            self._run_action(lambda: self.model.import_trace_file(path, self._authorization()), f"Imported {Path(path).name}.")

        def _fetch_network(self) -> None:
            allowed = tuple(part.strip() for part in self.allowed_host_var.get().split(",") if part.strip())
            self._run_action(
                lambda: self.model.fetch_network_observation(
                    url=self.url_var.get(),
                    authorization=self._authorization(),
                    allowed_hosts=allowed,
                    include_body=self.include_body_var.get(),
                ),
                "Fetched network observation.",
            )

        def _calibration_path_values(self) -> tuple[str, ...]:
            raw = self.calibration_paths.get("1.0", "end")
            return tuple(line.strip() for line in raw.splitlines() if line.strip())

        def _calibrate_target(self) -> None:
            self._run_action(
                lambda: self.model.calibrate_target(
                    base_url=self.calibration_base_var.get(),
                    paths=self._calibration_path_values(),
                    authorization=self._authorization(),
                    mask_name=self.mask_name_var.get(),
                    version=self.version_var.get(),
                    global_tolerance=float(self.tolerance_var.get()),
                    calibration_preset=self.preset_var.get(),
                    include_body=self.include_body_var.get(),
                ),
                "Calibrated target.",
            )

        def _build_mask(self) -> None:
            self._run_action(
                lambda: self.model.build_mask(
                    name=self.mask_name_var.get(),
                    version=self.version_var.get(),
                    global_tolerance=float(self.tolerance_var.get()),
                    calibration_preset=self.preset_var.get(),
                ),
                "Built operational mask.",
            )

        def _build_plan(self) -> None:
            self._run_action(
                lambda: self.model.build_plan(
                    authorization=self._authorization(),
                    objective=self.objective_var.get(),
                    operator_names=self._selected_operators(),
                ),
                "Built adapter plan.",
            )

        def _run_iteration(self) -> None:
            self._run_action(
                lambda: self.model.run_iteration(
                    authorization=self._authorization(),
                    operator_names=self._selected_operators(),
                ),
                "Ran recursive iteration.",
            )

        def _export_plan(self) -> None:
            path = self._filedialog.asksaveasfilename(
                title="Export plan",
                defaultextension=".json",
                filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            )
            if not path:
                return
            self._run_action(lambda: self.model.export_plan(path), f"Exported plan to {Path(path).name}.")

        def _export_ledger(self) -> None:
            path = self._filedialog.asksaveasfilename(
                title="Export audit",
                defaultextension=".jsonl",
                filetypes=(("JSONL", "*.jsonl"), ("All files", "*.*")),
            )
            if not path:
                return
            self._run_action(lambda: self.model.export_ledger(path), f"Exported audit to {Path(path).name}.")

        def _clear(self) -> None:
            self.model.clear()
            self._set_output("Ready.")
            self._wire_state()

        def _run_action(self, action, success: str) -> None:
            try:
                action()
            except Exception as exc:
                self._messagebox.showerror("Action failed", str(exc))
                self._set_output(f"Error: {exc}")
            else:
                self._set_output(f"{success}\n\n{self._status_text()}")
            finally:
                self._wire_state()

        def _status_text(self) -> str:
            snap = self.model.snapshot()
            lines = [
                f"Observations: {snap.object_count}",
                f"Mask: {snap.mask_name or '-'}",
                f"Plan: {snap.plan_decision or '-'}",
                f"Feedback: {snap.feedback_score if snap.feedback_score is not None else '-'}",
                f"Iteration: {snap.iteration_stop_reason or '-'}",
                f"Audit entries: {snap.ledger_entries}",
            ]
            if self.model.plan:
                lines.append("")
                lines.append(self.model.plan_summary())
            if self.model.iteration_result:
                lines.append("")
                lines.append(self.model.iteration_summary())
            if self.model.objects:
                lines.append("")
                lines.append(json.dumps(self.model.fingerprint_summary(), indent=2, sort_keys=True))
            return "\n".join(lines)

        def _set_output(self, text: str) -> None:
            self.output.configure(state="normal")
            self.output.delete("1.0", "end")
            self.output.insert("1.0", text)
            self.output.configure(state="disabled")

        def _wire_state(self) -> None:
            auth_ready = all(
                value.strip()
                for value in (self.source_var.get(), self.owner_var.get(), self.permission_var.get())
            )
            has_objects = bool(self.model.objects)
            actions = self.model.action_state(
                auth_ready=auth_ready,
                url_ready=bool(self.url_var.get().strip()),
                network_authorized=self.network_auth_var.get(),
                selected_operator_count=len(self._selected_operators()),
                calibration_ready=bool(self.calibration_base_var.get().strip()),
            )
            self.load_button.configure(state="normal" if actions.import_trace else "disabled")
            self.fetch_button.configure(state="normal" if actions.fetch_network else "disabled")
            self.calibrate_button.configure(state="normal" if actions.calibrate_target else "disabled")
            self.mask_button.configure(state="normal" if has_objects else "disabled")
            self.plan_button.configure(state="normal" if actions.build_plan else "disabled")
            self.iteration_button.configure(state="normal" if actions.run_iteration else "disabled")
            self.export_plan_button.configure(state="normal" if actions.export_plan else "disabled")
            self.export_ledger_button.configure(state="normal" if actions.export_ledger else "disabled")

    app = ChameleonTkApp()
    app.mainloop()


if __name__ == "__main__":
    main()
