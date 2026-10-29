# Contributing to AIGIS

AIGIS is an open-source protocol donated to the AI industry. Contributions are welcome.

## Ground rules

- **All changes go through pull requests.** `main` is protected: no direct pushes, no force pushes.
- Every PR needs: passing CI, a `CHANGELOG.md` entry, a completed PR checklist, and code-owner approval.
- By contributing, you agree your contributions are licensed under the MIT License.

## How to contribute

1. **Fork** this repository.
2. Create a branch: `feature/<name>`, `fix/<name>`, `docs/<name>`, or `protocol/<name>`.
3. Make your change. Build and test locally (Java 21 required, Maven is bundled):
   ```bash
   ./mvnw clean verify
   ```
4. Add a line under `## [Unreleased]` in `CHANGELOG.md` (Added / Changed / Fixed / Removed / Security).
5. Open a **Pull Request** and complete the template.

PRs that only touch docs or CI may use the `skip-changelog` label (maintainers apply it).

## Protocol changes (`SPECIFICATION.md`)

The specification is the standard others implement, so it changes deliberately:

1. Open an issue using **Protocol change proposal** describing the problem, the proposed text, and compatibility impact.
2. After discussion, open a PR labelled `protocol-change` that updates `SPECIFICATION.md`, bumps its version
   header, and adds a CHANGELOG entry.
3. Versioning: **MAJOR** for breaking changes (serial format, required fields, endpoint semantics),
   **MINOR** for backward-compatible additions, **PATCH** for clarifications.
4. Protocol changes require maintainer approval and should keep the reference implementation in step
   (or link an issue tracking the follow-up).

## Dependency upgrades

Dependabot opens weekly PRs for Maven and GitHub Actions. Each is reviewed, must pass CI, and is noted in the
changelog under **Changed** (or **Security** for vulnerability fixes). Versions are pinned in `pom.xml` properties.

## What we're looking for

- Closing the ⏳ items in the README's *Specification vs. Reference Implementation* table
  (persistence, path ledger, Ed25519 signing, mandate attenuation, RFC 9421)
- Reference implementations in other languages
- Integration guides for specific AI platforms and agent frameworks
- Security audits and vulnerability reports (privately — see `SECURITY.md`)
- Documentation and translations

## Releasing (maintainers)

1. Move `[Unreleased]` entries to a new version heading with the date.
2. Update `<version>` in `pom.xml` (and `SPECIFICATION.md` if the protocol changed).
3. Merge, then tag `vX.Y.Z` on `main`. The release workflow builds and attaches `aigis.jar` to the GitHub Release.

## Code of Conduct

Be respectful. Be constructive. Focus on making AI safer for everyone.
