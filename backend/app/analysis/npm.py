import json

from app.analysis.types import (
    DEVELOPMENT,
    PRODUCTION,
    ManifestError,
    PackageRef,
    ParsedComponent,
    ParsedManifest,
    is_storable,
)

ECOSYSTEM = "npm"


def _resolve(path: str, name: str, known: set[str]) -> str | None:
    current = path
    while True:
        candidate = f"{current}/node_modules/{name}" if current else f"node_modules/{name}"
        if candidate in known:
            return candidate
        if not current:
            return None
        marker = current.rfind("node_modules/")
        current = current[:marker].rstrip("/") if marker > 0 else ""


def parse_package_lock(content: str) -> ParsedManifest:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ManifestError("package-lock.json is not valid JSON") from None

    if (
        not isinstance(data, dict)
        or data.get("lockfileVersion") not in (2, 3)
        or not isinstance(data.get("packages"), dict)
    ):
        raise ManifestError("Only package-lock.json with lockfileVersion 2 or 3 (npm 7+) is supported")

    packages = data["packages"]
    root = packages.get("")
    root = root if isinstance(root, dict) else {}

    refs: dict[str, PackageRef] = {}
    entries: dict[str, dict] = {}
    skipped = 0
    for path, entry in packages.items():
        if not path or "node_modules/" not in path:
            continue
        if not isinstance(entry, dict) or entry.get("link"):
            skipped += 1
            continue
        version = entry.get("version")
        name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
        if not isinstance(version, str) or not isinstance(name, str) or not is_storable(name, version):
            skipped += 1
            continue
        refs[path] = PackageRef(ECOSYSTEM, name, version)
        entries[path] = entry

    if not refs:
        raise ManifestError("No installable dependencies found in package-lock.json")

    known = set(refs)
    direct_refs: set[PackageRef] = set()
    for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
        declared = root.get(field_name, {})
        if isinstance(declared, dict):
            for dependency_name in declared:
                resolved = _resolve("", dependency_name, known)
                if resolved:
                    direct_refs.add(refs[resolved])

    scopes: dict[PackageRef, str] = {}
    for path, ref in refs.items():
        is_dev = bool(entries[path].get("dev") or entries[path].get("devOptional"))
        if scopes.get(ref) != PRODUCTION:
            scopes[ref] = DEVELOPMENT if is_dev else PRODUCTION

    edges: set[tuple[PackageRef, PackageRef]] = set()
    for path, ref in refs.items():
        for field_name in ("dependencies", "optionalDependencies"):
            declared = entries[path].get(field_name, {})
            if not isinstance(declared, dict):
                continue
            for dependency_name in declared:
                child_path = _resolve(path, dependency_name, known)
                if child_path and refs[child_path] != ref:
                    edges.add((ref, refs[child_path]))

    components = [
        ParsedComponent(ref, ref in direct_refs, scopes[ref])
        for ref in sorted(scopes, key=lambda item: (item.name, item.version))
    ]
    warnings = []
    if skipped:
        warnings.append(f"Skipped {skipped} entries without a usable name or version (links, workspaces or oversized fields)")
    sorted_edges = sorted(edges, key=lambda e: (e[0].name, e[0].version, e[1].name, e[1].version))
    return ParsedManifest(ECOSYSTEM, components, sorted_edges, warnings)