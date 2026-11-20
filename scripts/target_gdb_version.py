from pathlib import Path


_versions_file = Path(__file__).resolve().parents[1] / "gdb-build" / "versions.env"

def get_gdb_version() -> str:
    for line in _versions_file.read_text().splitlines():
        key, _, value = line.partition("=")
        if key == "GDB_VERSION":
            return value.strip()
    raise ValueError(f"GDB_VERSION missing from {_versions_file}")
