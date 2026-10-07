import re
from collections.abc import Iterator

from app.analysis.types import (
    PRODUCTION,
    ManifestError,
    PackageRef,
    ParsedComponent,
    ParsedManifest,
    is_storable,
)

ECOSYSTEM = "PyPI"
PINNED = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$"
)
MAX_LISTED_WARNINGS = 10


def _logical_lines(content: str) -> Iterator[str]:
    buffer = ""
    for raw in content.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        yield buffer + line
        buffer = ""
    if buffer:
        yield buffer


def parse_requirements(content: str) -> ParsedManifest:
    components: dict[PackageRef, ParsedComponent] = {}
    skipped: list[str] = []

    for line in _logical_lines(content):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("-"):
            skipped.append(f"Ignored option line '{text[:60]}'")
            continue
        text = re.split(r"\s#", text)[0]
        text = text.split(";")[0]
        text = re.split(r"\s+--", text)[0].strip()
        match = PINNED.match(text)
        if not match:
            skipped.append(f"Skipped '{text[:60]}' (exact == pin required)")
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        version = match.group(2)
        if not is_storable(name, version):
            skipped.append(f"Skipped '{text[:60]}' (name or version too long)")
            continue
        ref = PackageRef(ECOSYSTEM, name, version)
        components[ref] = ParsedComponent(ref, True, PRODUCTION)

    if not components:
        raise ManifestError("No pinned requirements found; use exact versions such as name==1.2.3")

    warnings = skipped[:MAX_LISTED_WARNINGS]
    if len(skipped) > MAX_LISTED_WARNINGS:
        warnings.append(f"{len(skipped) - MAX_LISTED_WARNINGS} more lines were skipped")
    warnings.append("requirements.txt lists declared packages only; transitive dependencies are not resolved")

    ordered = sorted(components.values(), key=lambda c: (c.ref.name, c.ref.version))
    return ParsedManifest(ECOSYSTEM, ordered, [], warnings)