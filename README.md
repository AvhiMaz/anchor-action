# Anchor Security Audit

Static security analysis for Solana Anchor programs. Runs on pull requests and comments findings directly on the PR.

## Usage

```yaml
name: Anchor Security

on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - uses: actions/checkout@v4
      - uses: avhidotsol/anchor-audit-action@v1
```

## Configuration

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` |
| `fail_on` | Minimum severity to fail CI: `high`, `medium`, `low`, `none` | `high` |
| `github_token` | GitHub token for PR comments | `${{ github.token }}` |

### Example with options

```yaml
- uses: avhidotsol/anchor-audit-action@v1
  with:
    path: "programs/"
    fail_on: "medium"
```

## Checks

### High Severity

**unchecked-account** — Raw `AccountInfo` fields in `#[derive(Accounts)]` structs without a `/// CHECK:` safety comment. These bypass Anchor's type-safe deserialization.

**invoke-signed-no-bump** — `invoke_signed` calls without bump seed validation. Missing bump verification can enable PDA collision attacks.

**pda-program-id** — PDA derivation (`find_program_address` / `create_program_address`) without verifying the program ID. An attacker could substitute a PDA from a different program.

### Medium Severity

**missing-constraint** — Account fields with `#[account]` attribute but no constraints (`has_one`, `constraint`, `seeds`, `address`). These accounts are not validated against expected state.

**cpi-missing-signer-check** — CPI `invoke` calls without visible signer validation in surrounding code. Accounts passed to cross-program invocations should be explicitly checked.

**pda-create-unverified** — Use of `create_program_address` instead of `find_program_address`. The latter returns the bump and is the safer pattern.

## Outputs

| Output | Description |
|--------|-------------|
| `finding-count` | Total number of findings |
| `has-high` | `true` if any high severity findings |
| `has-medium` | `true` if any medium+ severity findings |

## PR Comment

When issues are found, the action posts a structured comment on the PR:

```
## Anchor Security Report

3 issue(s) found across 12 files scanned.

### High Severity

- [unchecked-account] in `programs/vault/src/lib.rs:45`
  Raw `AccountInfo` field `authority` without `/// CHECK:` comment.

### Medium Severity

- [missing-constraint] in `programs/vault/src/lib.rs:32`
  Field `vault` has `#[account]` without constraints.
```

## Local Usage

```sh
cargo install --path .
anchor-audit
```

Set `INPUT_PATH` to target a specific directory:

```sh
INPUT_PATH=programs/ anchor-audit
```

## License

MIT
