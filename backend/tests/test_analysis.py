import json

import pytest

from app.analysis.npm import parse_package_lock
from app.analysis.pypi import parse_requirements
from app.analysis.types import ManifestError, PackageRef, ParsedComponent, ParsedManifest
from app.risk.attack_paths import describe_path, shortest_paths


def ref(name, version="1.0.0", ecosystem="npm"):
    return PackageRef(ecosystem, name, version)


def lock(packages):
    return json.dumps({"lockfileVersion": 3, "packages": packages})


def test_npm_classifies_direct_transitive_and_scope():
    manifest = parse_package_lock(
        lock(
            {
                "": {"dependencies": {"express": "^4"}, "devDependencies": {"mocha": "^8"}},
                "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0"}},
                "node_modules/qs": {"version": "6.7.0"},
                "node_modules/mocha": {"version": "8.0.1", "dev": True, "dependencies": {"debug": "4"}},
                "node_modules/debug": {"version": "4.1.1", "dev": True},
            }
        )
    )
    components = {c.ref.name: c for c in manifest.components}
    assert components["express"].is_direct and components["mocha"].is_direct
    assert not components["qs"].is_direct and not components["debug"].is_direct
    assert components["express"].scope == "production"
    assert components["mocha"].scope == components["debug"].scope == "development"
    assert (ref("express", "4.17.1"), ref("qs", "6.7.0")) in manifest.edges


def test_npm_resolves_nested_package_versions():
    manifest = parse_package_lock(
        lock(
            {
                "": {"dependencies": {"a": "1", "b": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "2"}},
                "node_modules/b": {"version": "1.0.0"},
                "node_modules/a/node_modules/b": {"version": "2.0.0"},
            }
        )
    )
    assert (ref("a"), ref("b", "2.0.0")) in manifest.edges
    assert (ref("a"), ref("b", "1.0.0")) not in manifest.edges
    assert {c.ref.version for c in manifest.components if c.ref.name == "b"} == {"1.0.0", "2.0.0"}


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"lockfileVersion": 1, "dependencies": {}}),
        json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "empty"}}}),
        json.dumps([1, 2, 3]),
    ],
)
def test_npm_rejects_unusable_files(content):
    with pytest.raises(ManifestError):
        parse_package_lock(content)


REQUIREMENTS = """\
# comment line
Django==3.2.0
requests[security]==2.19.0 ; python_version >= "3.8"
PyYAML == 5.3.1  # trailing comment
flask>=1.0
-r other.txt
git+https://github.com/example/project.git#egg=project
Jinja2==2.10 \\
    --hash=sha256:abc
"""


def test_requirements_parses_pinned_packages_and_normalizes_names():
    manifest = parse_requirements(REQUIREMENTS)
    found = {(c.ref.name, c.ref.version) for c in manifest.components}
    assert found == {("django", "3.2.0"), ("requests", "2.19.0"), ("pyyaml", "5.3.1"), ("jinja2", "2.10")}
    assert all(c.is_direct and c.scope == "production" for c in manifest.components)
    assert manifest.edges == []


def test_requirements_reports_skipped_lines():
    warnings = " ".join(parse_requirements(REQUIREMENTS).warnings)
    assert "flask" in warnings
    assert "other.txt" in warnings
    assert "transitive" in warnings


def test_requirements_without_pins_is_rejected():
    with pytest.raises(ManifestError):
        parse_requirements("requests>=2.0\nflask\n")


def manifest_of(components, edges):
    return ParsedManifest(
        "npm", [ParsedComponent(item, direct, "production") for item, direct in components], edges
    )


def test_shortest_path_is_deterministic():
    a, b, c, d = ref("a"), ref("b"), ref("c"), ref("d")
    manifest = manifest_of([(a, True), (b, False), (c, False), (d, False)], [(a, c), (a, b), (b, d), (c, d)])
    assert shortest_paths(manifest, {d})[d] == [a, b, d]


def test_direct_target_has_single_step_path_and_unreachable_is_missing():
    a, orphan = ref("a"), ref("orphan")
    manifest = manifest_of([(a, True), (orphan, False)], [])
    paths = shortest_paths(manifest, {a, orphan})
    assert paths[a] == [a]
    assert orphan not in paths


def test_describe_path_marks_entry_point_and_vulnerable_node():
    express, qs = ref("express", "4.17.1"), ref("qs", "6.7.0")
    components = {
        express: ParsedComponent(express, True, "production"),
        qs: ParsedComponent(qs, False, "production"),
    }
    path = describe_path([express, qs], components, internet_facing=True)
    assert [node["label"] for node in path["nodes"]] == ["Application", "express@4.17.1", "qs@6.7.0"]
    assert path["through_entry_point"] is True
    assert path["exposure"] == "internet-facing"
    assert path["nodes"][-1]["vulnerable"] is True
    assert path["nodes"][1]["type"] == "direct" and path["nodes"][2]["type"] == "transitive"