# Releasing

Releases are published to both GitHub and npm. The current process uses a release-preparation pull request, a lightweight Git tag, a GitHub release, and an npm publish authorized with two-factor authentication.

## Preconditions

- Start from a clean, synchronized `main` branch.
- Confirm `gh auth status` and `npm whoami` identify the intended accounts.
- Confirm npm two-factor authentication is enabled for publishing.
- Check that the target version and Git tag do not already exist.

## Prepare the release

1. Create an `agent/release-X.Y.Z` branch from `origin/main`.
2. Update the version in `package.json` and both root-package version fields in `package-lock.json`.
3. Add a dated `CHANGELOG.md` entry describing user-visible changes and security boundaries.
4. Update version-pinned README examples, including the browser-bundle CDN URL.
5. Regenerate committed output when source or build tooling changed.

Use semantic versioning. Documentation corrections that change the README shipped on npm require a new patch version because an existing npm version cannot be republished.

## Validate

Run the normal release gates:

```bash
npm ci
npm audit
npm test
npm run build
npm run build:browser
git diff --exit-code -- dist
npm pack --dry-run --json
```

CI also installs `@phala/dcap-qvl@0.6.1` outside the default lockfile and runs:

```bash
DCAP_COMPAT_TEST=1 npm test -- src/dcap.test.ts
```

Reproduce that job only in a disposable checkout because its preceding `npm install --save-dev --package-lock=false --ignore-scripts @phala/dcap-qvl@0.6.1` command temporarily changes `package.json` and `node_modules`.

## Merge and tag

1. Commit only the intended release files and push the release branch.
2. Open a ready-for-review pull request into `main` with the validation results.
3. Wait for CI, DCAP compatibility, dependency review, CodeQL, and configured external reviews.
4. Merge the pull request and fetch the resulting `main` commit.
5. Verify the merged commit contains the intended package version and changelog.
6. Create a lightweight `vX.Y.Z` tag at that exact commit and push it.
7. Create a non-prerelease GitHub release using the changelog entry as its notes.
8. Wait for post-merge CI and CodeQL to pass on the tagged commit.

## Publish to npm

From a clean checkout at the exact release tag:

```bash
npm publish --access public
```

Approve npm's browser-based two-factor authentication prompt when requested. Never paste npm tokens, recovery codes, or one-time passwords into logs or pull requests.

Verify the registry result:

```bash
npm view venice-e2ee name version dist-tags maintainers repository license dist.integrity --json
npm owner ls venice-e2ee
```

Finally, install `venice-e2ee@X.Y.Z` into a fresh temporary directory and import the root package plus the `dcap` and `nvidia` subpaths.

## Automation follow-up

The manual process is suitable for bootstrapping the package. Before routine releases, configure npm trusted publishing from a narrowly scoped GitHub Actions workflow and enable package provenance so releases no longer depend on a workstation credential.
