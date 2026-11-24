"""Allow ``python -m sigil``."""

from sigil.desktop.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
