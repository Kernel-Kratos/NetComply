"""Reset local database and reload seed mappings. Owner: P2."""
from __future__ import annotations

from core.mappings import reset_db


def main() -> None:
    print("Resetting local mappings database and re-seeding from JSON...")
    reset_db()
    print("Reset complete. Ready for demo!")


if __name__ == "__main__":
    main()