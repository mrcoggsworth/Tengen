"""UDM parser — turns raw incoming alerts into :class:`UDMEvent`.

The parser leans on the existing source normalizers (which already map the
well-known fields) to produce a :class:`NormalizedEvent`, then projects that
onto a :class:`UDMEvent` via ``to_udm()``. Separately it walks the raw payload
to find any leaf field the model does not yet cover, records each in the field
registry, and stashes the values under ``UDMEvent.additional`` so nothing is
lost while the field awaits promotion into the model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tengen.models.normalized_event import LogSourceType, NormalizedEvent
from tengen.models.udm import UDMEvent
from tengen.udm.field_registry import FieldRegistry
from tengen.udm.mappings import CONSUMED_PATHS, flatten, suggest_udm_field


@dataclass(frozen=True)
class FieldObservation:
    """A raw field the UDM model does not yet represent."""

    source_type: str
    raw_path: str
    sample_value: Any
    suggested_udm_field: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "raw_path": self.raw_path,
            "sample_value": self.sample_value,
            "suggested_udm_field": self.suggested_udm_field,
        }


@dataclass
class UDMParseResult:
    """Output of a parse: the UDM event, the intermediate normalized event,
    and the list of unmapped fields discovered."""

    udm: UDMEvent
    normalized: NormalizedEvent
    unmapped: list[FieldObservation] = field(default_factory=list)


class UDMParser:
    """Parses raw alerts into UDM and discovers/records new fields.

    Pass a :class:`FieldRegistry` to persist discovered fields; omit it for a
    pure, side-effect-free parse.
    """

    def __init__(self, registry: FieldRegistry | None = None) -> None:
        self.registry = registry

    def detect_source_type(self, raw: dict[str, Any]) -> LogSourceType:
        from tengen.tools.normalizers.registry import detect_source_type

        return detect_source_type(raw)

    def discover_unmapped(
        self, raw: dict[str, Any], source_type: LogSourceType
    ) -> list[FieldObservation]:
        """Return raw leaf fields not already consumed by the normalizer."""
        consumed = CONSUMED_PATHS.get(source_type, set())
        observations: list[FieldObservation] = []
        for path, value in flatten(raw).items():
            if path in consumed:
                continue
            observations.append(
                FieldObservation(
                    source_type=source_type.value,
                    raw_path=path,
                    sample_value=value,
                    suggested_udm_field=suggest_udm_field(path, value),
                )
            )
        return observations

    def parse(
        self,
        raw: dict[str, Any],
        source_type: LogSourceType | None = None,
        record: bool = True,
    ) -> UDMParseResult:
        """Parse ``raw`` into a :class:`UDMParseResult`.

        When ``record`` is true and a registry was provided, every discovered
        unmapped field is written to the registry.
        """
        from tengen.tools.normalizers.registry import normalize

        if source_type is None:
            source_type = self.detect_source_type(raw)

        normalized = normalize(raw, source_type)
        # normalize() may re-derive the source type (e.g. OpenShift vs K8s).
        effective_source = normalized.source_type
        udm = normalized.to_udm()

        unmapped = self.discover_unmapped(raw, effective_source)

        if unmapped:
            # Preserve unmapped values on the UDM event so nothing is dropped.
            udm.additional.setdefault("unmapped", {})
            for obs in unmapped:
                udm.additional["unmapped"][obs.raw_path] = obs.sample_value
            if record and self.registry is not None:
                for obs in unmapped:
                    self.registry.observe(
                        source_type=obs.source_type,
                        raw_path=obs.raw_path,
                        sample_value=obs.sample_value,
                        suggested_udm_field=obs.suggested_udm_field,
                    )

        return UDMParseResult(udm=udm, normalized=normalized, unmapped=unmapped)
