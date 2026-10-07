from dataclasses import dataclass, field
from urllib.parse import quote

PRODUCTION = "production"
DEVELOPMENT = "development"


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class PackageRef:
    ecosystem: str
    name: str
    version: str

    @property
    def purl(self) -> str:
        kind = "npm" if self.ecosystem == "npm" else "pypi"
        return f"pkg:{kind}/{quote(self.name, safe='/')}@{quote(self.version, safe='')}"


@dataclass
class ParsedComponent:
    ref: PackageRef
    is_direct: bool
    scope: str


@dataclass
class ParsedManifest:
    ecosystem: str
    components: list[ParsedComponent]
    edges: list[tuple[PackageRef, PackageRef]]
    warnings: list[str] = field(default_factory=list)


def is_storable(name: str, version: str) -> bool:
    return 0 < len(name) <= 255 and 0 < len(version) <= 100