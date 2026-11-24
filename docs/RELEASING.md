# Releasing Sigil

For the maintainer. A release is published automatically when a version tag is pushed.

## Versions and fruit codenames

Versions follow [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`.
Every **minor** version gets the next fruit codename, alphabetically; patch releases keep
their minor version's fruit.

| Version | Codename | | Version | Codename |
|---|---|---|---|---|
| 1.0.x | **Apricot** | | 1.11.x | Mango |
| 1.1.x | Banana | | 1.12.x | Nectarine |
| 1.2.x | Cherry | | 1.13.x | Olive |
| 1.3.x | Date | | 1.14.x | Papaya |
| 1.4.x | Elderberry | | 1.15.x | Quince |
| 1.5.x | Fig | | 1.16.x | Raspberry |
| 1.6.x | Guava | | 1.17.x | Strawberry |
| 1.7.x | Honeydew | | 1.18.x | Tangerine |
| 1.8.x | Jackfruit | | 1.19.x | Ugli |
| 1.9.x | Kiwi | | 1.20.x | Watermelon |
| 1.10.x | Lemon | | 1.21.x | Yuzu |

A new major version continues with the next unused fruit. The sequence lives in
`CODENAMES` in `src/sigil/__init__.py`, and `tests/unit/test_versioning.py` checks that the
codename matches the version.

The version and codename are set in **one place**, `src/sigil/__init__.py`
(`__version__`, `__codename__`); `pyproject.toml` reads the version from there. The codename
appears in `sigil version`, `/api/v1/health`, the tray menu and the release title.

## Cutting a release

1. On a branch from `main`, update `src/sigil/__init__.py`:
   - `__version__ = "1.1.0"`
   - `__codename__ = "Banana"` (only when the minor version changes)
2. In `CHANGELOG.md`, rename **Unreleased** to `## 1.1.0 "Banana" — YYYY-MM-DD` and add a new
   empty **Unreleased** section above it.
3. Open a pull request; when **All checks passed** is green, squash-merge it.
4. Tag the merged commit on `main` and push the tag:
   ```bash
   git switch main && git pull
   git tag -a v1.1.0 -m 'Sigil 1.1.0 "Banana"'
   git push origin v1.1.0
   ```
5. The pipeline tests and builds on Windows, macOS and Linux, checks that the tag matches
   `__version__`, and publishes **Sigil v1.1.0 — Banana** on the Releases page with:
   - `sigil-windows-x64.exe`
   - `Sigil-macos-arm64.zip`
   - `sigil-linux-x64.tar.gz`
   - `SHA256SUMS.txt`

Tags with a suffix, such as `v1.1.0-rc1`, are published as **pre-releases** (set
`__version__ = "1.1.0-rc1"` for them).

If the release job fails because the tag and version don't match, fix the version in a new
PR and push a new tag. Version tags cannot be moved or deleted (see below).

## Repository rules

The rules live in `.github/rulesets/` and are applied once in GitHub's settings:
**Settings → Rules → Rulesets → New ruleset → Import a ruleset**, pick the file, review it,
then click **Create**. Import all three:

| File | Applies to | Effect |
|---|---|---|
| `main.json` | the default branch | Changes only through pull requests whose **All checks passed** check is green and whose branch is up to date; squash-merge only (linear history); signed commits; no force-push or deletion. No approvals are required, so the maintainer can merge their own PRs. |
| `release-tags-create.json` | tags `v*` | Only repository admins can create version tags. |
| `release-tags-immutable.json` | tags `v*` | Nobody can move, force-push or delete a version tag, so a published release always points at the same code. |

When importing `release-tags-create.json`, check that the bypass list shows
**Repository admin**. If it is empty or shows another role, remove the entry and add
**Repository admin** with **Add bypass**.

To remove a version tag in an emergency, temporarily set the "Release tags: immutable"
ruleset to **Disabled**, then re-enable it.

Also worth enabling under **Settings → Code security**: Dependabot alerts and
**Private vulnerability reporting** (the issue form's "Report a security vulnerability"
link points there).
