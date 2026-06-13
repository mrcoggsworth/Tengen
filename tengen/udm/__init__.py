"""UDM parsing layer.

Parses incoming alerts into Tengen's Unified Data Model
(:class:`tengen.models.udm.UDMEvent`) and tracks raw fields that do not yet map
onto the model in a low-resource field registry, so they can be reviewed and
promoted into the model via a branch + pull request.
"""
from tengen.udm.field_registry import FieldRegistry, FieldStatus
from tengen.udm.parser import FieldObservation, UDMParser, UDMParseResult

__all__ = [
    "FieldRegistry",
    "FieldStatus",
    "FieldObservation",
    "UDMParser",
    "UDMParseResult",
]
