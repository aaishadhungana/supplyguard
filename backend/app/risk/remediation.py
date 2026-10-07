def remediation_hint(package: str, is_direct: bool, fixed_versions: list[str]) -> str:
    if not fixed_versions:
        return f"No fixed version is listed for {package}; review the advisory for mitigations."
    listed = ", ".join(fixed_versions[:5])
    hint = f"Upgrade {package} to a fixed version: {listed}."
    if not is_direct:
        hint += " This is a transitive dependency, so update the parent package or add a version override."
    return hint