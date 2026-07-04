from __future__ import annotations

from dataclasses import dataclass


DEFAULT_CALIBRATION_PRESET = "Domain surface"


@dataclass(frozen=True)
class CalibrationPreset:
    name: str
    dimensions: tuple[str, ...]
    dimension_tolerances: dict[str, float]
    global_tolerance: float
    residue_externalization_surfaces: tuple[str, ...] = ("semantic", "linkability")
    notes: tuple[str, ...] = ()


CALIBRATION_PRESETS: dict[str, CalibrationPreset] = {
    "Domain surface": CalibrationPreset(
        name="Domain surface",
        dimensions=(
            "shape",
            "ordering",
            "entropy",
            "timing",
            "semantic",
            "linkability",
            "http_surface",
            "http_header_order",
            "body_schema",
            "transport_timing",
            "linkability_surface",
        ),
        dimension_tolerances={
            "shape": 0.35,
            "ordering": 0.35,
            "entropy": 0.80,
            "timing": 1.00,
            "semantic": 0.35,
            "linkability": 0.35,
            "http_surface": 0.45,
            "http_header_order": 0.60,
            "body_schema": 0.65,
            "transport_timing": 0.80,
            "linkability_surface": 0.35,
        },
        global_tolerance=0.70,
        notes=("broad domain or service baseline",),
    ),
    "HTTP fingerprint": CalibrationPreset(
        name="HTTP fingerprint",
        dimensions=("http_surface", "http_header_order", "body_schema", "transport_timing", "linkability_surface"),
        dimension_tolerances={
            "shape": 0.50,
            "ordering": 0.50,
            "entropy": 0.80,
            "timing": 0.80,
            "semantic": 0.45,
            "linkability": 0.35,
            "http_surface": 0.22,
            "http_header_order": 0.25,
            "body_schema": 0.30,
            "transport_timing": 0.35,
            "linkability_surface": 0.20,
        },
        global_tolerance=0.40,
        notes=("protocol-specific HTTP response and timing fingerprint",),
    ),
    "Endpoint shape": CalibrationPreset(
        name="Endpoint shape",
        dimensions=("shape", "ordering", "semantic", "entropy", "http_surface", "body_schema"),
        dimension_tolerances={
            "shape": 0.18,
            "ordering": 0.20,
            "entropy": 0.45,
            "timing": 1.50,
            "semantic": 0.20,
            "linkability": 0.60,
            "http_surface": 0.25,
            "http_header_order": 0.80,
            "body_schema": 0.35,
            "transport_timing": 1.20,
            "linkability_surface": 0.60,
        },
        global_tolerance=0.45,
        notes=("single route or small route family",),
    ),
    "API family": CalibrationPreset(
        name="API family",
        dimensions=("shape", "semantic", "entropy", "linkability", "http_surface", "body_schema"),
        dimension_tolerances={
            "shape": 0.28,
            "ordering": 0.50,
            "entropy": 0.65,
            "timing": 1.25,
            "semantic": 0.25,
            "linkability": 0.30,
            "http_surface": 0.30,
            "http_header_order": 0.70,
            "body_schema": 0.28,
            "transport_timing": 1.00,
            "linkability_surface": 0.30,
        },
        global_tolerance=0.60,
        notes=("method/status/header/body family",),
    ),
    "Timing stability": CalibrationPreset(
        name="Timing stability",
        dimensions=("timing", "entropy", "transport_timing"),
        dimension_tolerances={
            "shape": 0.80,
            "ordering": 0.80,
            "entropy": 0.70,
            "timing": 0.35,
            "semantic": 0.80,
            "linkability": 0.80,
            "http_surface": 0.80,
            "http_header_order": 0.90,
            "body_schema": 0.90,
            "transport_timing": 0.25,
            "linkability_surface": 0.80,
        },
        global_tolerance=0.55,
        notes=("latency and jitter focused baseline",),
    ),
    "Header/body surface": CalibrationPreset(
        name="Header/body surface",
        dimensions=("shape", "ordering", "entropy", "linkability", "http_header_order", "body_schema"),
        dimension_tolerances={
            "shape": 0.22,
            "ordering": 0.25,
            "entropy": 0.50,
            "timing": 1.50,
            "semantic": 0.45,
            "linkability": 0.22,
            "http_surface": 0.40,
            "http_header_order": 0.22,
            "body_schema": 0.22,
            "transport_timing": 1.20,
            "linkability_surface": 0.22,
        },
        global_tolerance=0.50,
        notes=("header count, body presence, payload-size surface",),
    ),
}


def calibration_spectrum() -> tuple[CalibrationPreset, ...]:
    return tuple(CALIBRATION_PRESETS[name] for name in CALIBRATION_PRESETS)


def calibration_preset_names() -> tuple[str, ...]:
    return tuple(CALIBRATION_PRESETS)


def get_calibration_preset(name: str | None) -> CalibrationPreset:
    if not name:
        return CALIBRATION_PRESETS[DEFAULT_CALIBRATION_PRESET]
    try:
        return CALIBRATION_PRESETS[name]
    except KeyError as exc:
        raise ValueError(f"unknown calibration preset: {name}") from exc
