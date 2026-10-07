from collections import defaultdict, deque

from app.analysis.types import PackageRef, ParsedComponent, ParsedManifest
from app.risk.roles import role_for

PATH_BASIS = (
    "Dependency chain taken from the lockfile. "
    "Whether the vulnerable code is reachable at runtime was not analyzed."
)


def _sort_key(ref: PackageRef) -> tuple[str, str]:
    return ref.name, ref.version


def shortest_paths(manifest: ParsedManifest, targets: set[PackageRef]) -> dict[PackageRef, list[PackageRef]]:
    children: dict[PackageRef, list[PackageRef]] = defaultdict(list)
    for parent, child in manifest.edges:
        children[parent].append(child)
    for key in children:
        children[key].sort(key=_sort_key)

    roots = sorted((c.ref for c in manifest.components if c.is_direct), key=_sort_key)
    parent_of: dict[PackageRef, PackageRef | None] = {}
    queue: deque[PackageRef] = deque()
    for root in roots:
        parent_of[root] = None
        queue.append(root)

    while queue:
        node = queue.popleft()
        for child in children.get(node, []):
            if child not in parent_of:
                parent_of[child] = node
                queue.append(child)

    paths: dict[PackageRef, list[PackageRef]] = {}
    for target in targets:
        if target not in parent_of:
            continue
        chain: list[PackageRef] = []
        node: PackageRef | None = target
        while node is not None:
            chain.append(node)
            node = parent_of[node]
        paths[target] = list(reversed(chain))
    return paths


def describe_path(
    chain: list[PackageRef],
    components: dict[PackageRef, ParsedComponent],
    internet_facing: bool,
) -> dict:
    nodes = [{"label": "Application", "type": "application", "role": None, "vulnerable": False}]
    for index, ref in enumerate(chain):
        nodes.append(
            {
                "label": f"{ref.name}@{ref.version}",
                "type": "direct" if components[ref].is_direct else "transitive",
                "role": role_for(ref),
                "vulnerable": index == len(chain) - 1,
            }
        )
    return {
        "established": True,
        "exposure": "internet-facing" if internet_facing else "internal",
        "length": len(chain),
        "through_entry_point": any(node["role"] == "web_framework" for node in nodes),
        "nodes": nodes,
        "basis": PATH_BASIS,
    }