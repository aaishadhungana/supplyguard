from collections.abc import Callable

from app.analysis.npm import parse_package_lock
from app.analysis.pypi import parse_requirements
from app.analysis.types import ManifestError, ParsedManifest

SUPPORTED_MANIFESTS: dict[str, Callable[[str], ParsedManifest]] = {
    "package-lock.json": parse_package_lock,
    "requirements.txt": parse_requirements,
}


def parse_manifest(filename: str, content: str) -> ParsedManifest:
    parser = SUPPORTED_MANIFESTS.get(filename)
    if parser is None:
        raise ManifestError(f"Unsupported manifest: {filename}")
    return parser(content)