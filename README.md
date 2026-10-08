# mprobe

`mprobe` is a Rust CLI for generating email-address candidates from configurable name combinations and, when explicitly requested, checking how a target domain's SMTP server responds to them.

## Install

```sh
cargo install --path .
```

## Examples

Shells expand `$variables` inside double quotes, so use **single quotes** around combination templates:

```sh
# Full help and bundled-list inventory
mprobe -h
mprobe -s

# Generate candidates using built-in first and last names
mprobe -t example.com -c '$fname.$lname'
mprobe -t example.com -c '$fname_$lname'
mprobe -t example.com -c '$fname-$lname'

# Positional files replace variables in first-appearance order
mprobe -t example.com -c '$fname.$lname' fname.txt lname.txt

# The named form is clearer and permits custom variables
mprobe -t example.com -c '$department.$fname' \
  -w department=departments.txt -w fname=staff.txt

# Actively ask the target MX servers about each candidate
mprobe -t example.com -c '$fname.$lname' fname.txt lname.txt --probe

# Optional tuning for a server you are authorized to test
mprobe -t example.com -c '$fname.$lname' fname.txt lname.txt --probe \
  --connections 8 --batch-size 50 -o results.txt

# JSON Lines output, 10,000 candidates
mprobe -t example.com -c '$fname.$lname' --limit 10000 --format jsonl -o candidates.jsonl
```

The default limit is 1,000 candidates because Cartesian products grow quickly. Use `--limit 0` to process every combination.

## Template variables

The bundled lists are `$fname`, `$lname`, `$petname`, and `$role`. `$domain` inserts the target domain. Braced forms such as `${fname}` are also accepted. Run `mprobe -s` to see counts and source files.

Each external file is newline-delimited. Blank lines and lines beginning with `#` are ignored; entries are lowercased, deduplicated, and reduced to characters valid in conventional email local parts.

## Fast probing

The normal `--probe` command automatically uses the optimized engine; no extra flags are required. It:

- resolves and caches MX socket addresses once;
- runs an SMTP preflight before starting the candidate set;
- keeps four SMTP connections open by default;
- checks candidates in batches of 25;
- automatically uses SMTP `PIPELINING` when the server advertises it;
- reconnects once after a transport failure and stops retrying the network after repeated failures;
- streams candidates through bounded queues and buffers result output.

`--connections` controls persistent sessions, and the previous name `--concurrency` remains an alias. `--batch-size` accepts 1–100. Larger settings are not always faster: providers may throttle or close clients that submit too many recipients.

Use `--no-pipelining` when diagnosing a server with a broken PIPELINING implementation. `--connect-timeout`, `--timeout`, and `--retries` control failure behavior; the defaults are intended to work without tuning. At completion, mprobe reports elapsed time, checks per second, and status totals.

Terminal headings, status labels, warnings, and errors use color plus bold/italic emphasis when output is attached to a terminal. Use `--color always` to force styling or `--color never` to disable it. Redirected output, result files, JSONL, and CSV remain unstyled by default.

Interactive runs also show the `mprobe` startup banner with blank-line separation from the shell command. Use `--no-banner` to hide only the banner or `--quiet` to suppress all informational terminal output.

## SMTP probing caveats

`--probe` performs `EHLO`, `MAIL FROM`, and `RCPT TO` without sending a message. `accepted` means the MX server returned an SMTP acceptance response at that moment; it does not prove that a mailbox is active or that a later message will be delivered. Many providers deliberately hide mailbox status, rate-limit checks, accept every recipient, or reject after message content is submitted. `mprobe` tests a random address first and warns if the domain appears to be catch-all. `unknown` does not mean a mailbox exists or does not exist.

Only probe domains you own or are authorized to assess. Keep connection count, batch size, and request volume appropriate for the target.

Generated probe output can contain email addresses, server responses, and network details. Keep it out of version control. The repository ignores root-level `*-debug.csv`, `result.txt`, and all JSON Lines output by default; add any other output paths to `.gitignore` before running probes.

## Development

Use the stable Rust toolchain with the `rustfmt` and `clippy` components. Run the same checks as GitHub Actions before opening a pull request:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
```

The CI workflow runs these checks for every push to `main` and for every pull request.

### Commit messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/). Enable the included commit-message hook once after cloning:

```sh
git config core.hooksPath .githooks
```

Commit subjects must use `type: summary` or `type(scope): summary`. Supported types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.

```text
feat: add SMTP preflight checks
fix(probe): stop retrying permanent failures
docs: clarify authorization requirements
```

GitHub Actions applies the same rule to every commit in a pull request.

## Wordlist provenance

`wordlists/fname.txt` is derived from `names.txt`, and `wordlists/lname.txt` from `top_family_names_usa.txt`, in [kkrypt0nn/wordlists](https://github.com/kkrypt0nn/wordlists/tree/main/wordlists/names). Entries are normalized at runtime. See [wordlists/NOTICE.md](wordlists/NOTICE.md).
