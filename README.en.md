# Garita

[Español](https://github.com/proscar87/garita/blob/main/README.md) · **English**

**Keeps personal data and credentials out of your repository.** Names from
your own records, official IDs from 16 countries across the Americas and the
Iberian peninsula (CURP, RFC, CLABE, CPF, CUIT, RUT, DNI, IBAN…), phone
numbers and secrets — as a `pre-commit` hook and as a GitHub Action.

## Why it exists

It came out of a common problem: a project where the financial records **had
to be** versioned — someone will audit them — and the roster of people could
**not** be. Privacy law regulates it and git history doesn't forget.

The rule that emerged sums up the tool:

> **The line is the unit, not the name.**
> You may version unit 47 and what it owes. Never the link between that unit
> and the person living in it.

Nothing existed to enforce it. Microsoft Presidio covers 20+ countries and
**Mexico isn't one**. GitGuardian **explicitly rejects** PII patterns.
GitHub charges for custom patterns, and they're secret patterns anyway — not
name lists. `git-secrets`, the only tool that could ban arbitrary strings, has
been unmaintained since 2019.

## The core idea

A guard that compares against a list written in its own config has a fatal
flaw: **the list is itself personal data**. To keep the roster out of the
repo, you'd have to write the roster into the repo.

The way out: most projects handling real data already have a **synthetic data
generator** for tests and seeds — and it already knows which real names it
must never produce by accident.

```yaml
nombres:
  - scripts/generate_fake_data.py:FORBIDDEN
```

Garita reads it from there **via AST, without executing the file**. One list,
impossible to desynchronise.

## What makes it different

**Mexican national IDs with checksum validation.** A detector that flags any
18-character string as a CURP cries wolf constantly — and a guard that cries
wolf gets ignored. With checksum validation, false positives drop by 90× to
5,000× depending on the identifier.

## Install

```yaml
# .pre-commit-config.yaml — start here
repos:
  - repo: https://github.com/proscar87/garita
    rev: v1.1.0
    hooks:
      - id: garita
```

```yaml
# .github/workflows/garita.yml — the backstop
- uses: actions/checkout@v4
- uses: proscar87/garita@v1
```

Hook first: if your only check is in CI, by the time it fails the data already
lives in a commit — and the fix goes from "delete a line" to "rewrite history
and notify everyone who cloned".

**Existing repo with prior findings?** Run `garita --linea-base` to freeze
them as accepted debt: CI then fails only on *new* findings, while old ones
stay visible in the report. The baseline file stores only counts per file and
detector — no values, no hashes — so it's safe to commit.

**And the past counts too:** `garita --historial` audits every version of
every file that ever passed through the repo — the secret committed three
months ago and "deleted" the next day is invisible to a normal scan, but git
never forgets. The report separates what's still in the tree from what lives
only in history, where the fix is rotating the credential — never a silent
history rewrite.

**A note on vocabulary**, since the config keys are in Spanish: `exenciones`
are what other tools call *exceptions*, *ignores* or an *allowlist* — each
one needs a written `motivo` (reason), and Garita refuses to run without it.
`nombres` is the list of names to protect, `clientes` the client list,
`paises` the country selection, `detectores` the on/off switches. Run
`garita --proponer-exenciones` and it writes the block for you, with the
reason left blank for you to fill in.

Config, findings format and design rationale: see the
[Spanish README](https://github.com/proscar87/garita/blob/main/README.md) and [`docs/DISENO.md`](https://github.com/proscar87/garita/blob/main/docs/DISENO.md). Built with
[Claude Code](https://claude.com/claude-code). MIT.

## Garita as a Secret Protection replacement

Garita can block credentials before a commit with pre-commit and scan the
repository in CI. It covers formats from AWS, Azure, Google, GitHub, GitLab,
Slack (tokens and webhooks), Stripe, Twilio, SendGrid, OpenAI, Anthropic,
Supabase, npm, DigitalOcean, Shopify, PyPI, Hugging Face, Vault, age,
Databricks, Doppler, Linear, Notion, Postman, Pulumi, Sentry, Grafana,
PlanetScale and Heroku. It also detects URLs with credentials, suspicious
assignments and PEM private keys with a body. Coverage depends on the format:
not every credential from each provider has a recognizable signature.
See the [coverage measurement](docs/COBERTURA_SECRETOS.md).

The existing `garita --historial` mode scans unique blobs in reachable history
and distinguishes current findings from those only present in older commits.
To scan all available history in CI, check out with `fetch-depth: 0`.

Garita does not automatically revoke credentials with the provider, verify
whether a key is valid, or reproduce GitHub Secret Protection's full catalog
of partner patterns. It does not install a barrier on GitHub's server:
the local hook can be skipped and CI runs after the upload. After a leak,
rotate the credential first, then clean up the file.

To adopt it, copy the [minimal workflow](docs/adopcion/garita.yml) to
`.github/workflows/garita.yml` and the [pre-commit block](docs/adopcion/pre-commit-config.yaml)
to `.pre-commit-config.yaml`; update the indicated tag and install the hook
with `pre-commit install`. Garita uses the Python standard library;
pre-commit is an optional integration tool.

Combine these controls with a nightly job (`schedule`, for example
`cron: '0 3 * * *'`) that checks out with `fetch-depth: 0` and runs a pinned
version of gitleaks installed on the runner:

```bash
gitleaks git . --log-opts="--all" --redact --report-format sarif --report-path gitleaks.sarif
garita --historial --formato html --salida garita-historial.html
```

Run both steps and retain reports even when a scan finds problems (in GitHub
Actions, use `if: always()` on the artifact upload step). In **private
repositories without Advanced Security**, SARIF uploads to code scanning are
unavailable: use the log or the HTML report as a workflow artifact. The minimal
workflow only needs `permissions: contents: read`.
