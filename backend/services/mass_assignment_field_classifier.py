from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_CANON_SENSITIVE_FIELDS: tuple[str, ...] = (
    "role",
    "roles",
    "isadmin",
    "admin",
    "status",
    "ownerid",
    "userid",
    "price",
    "balance",
    "verified",
    "permissions",
    "internal",
    "isinternal",
    "isstaff",
    "credit",
    "limit",
)

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


@dataclass(frozen=True)
class MassAssignmentFieldSelection:
    considered: list[str]
    selected: list[str]
    skipped: list[str]


def _norm_name(value: str) -> str:
    return re.sub(r"[_\-.]+", "", (value or "").strip().lower())


def is_mass_assignment_sensitive_field(field_name: str) -> bool:
    normalized = _norm_name(field_name)
    if not normalized:
        return False
    if normalized in _CANON_SENSITIVE_FIELDS:
        return True
    return any(normalized in canon or canon in normalized for canon in _CANON_SENSITIVE_FIELDS)


def select_mass_assignment_fields(fields: Iterable[str]) -> MassAssignmentFieldSelection:
    considered: list[str] = []
    selected: list[str] = []
    skipped: list[str] = []

    for raw in fields:
        field = str(raw or "").strip()
        if not field:
            continue
        if not _SAFE_NAME_RE.match(field):
            skipped.append(field[:64])
            continue
        considered.append(field)
        if is_mass_assignment_sensitive_field(field):
            selected.append(field)
        else:
            skipped.append(field)

    return MassAssignmentFieldSelection(
        considered=considered[:20],
        selected=selected[:20],
        skipped=skipped[:20],
    )
