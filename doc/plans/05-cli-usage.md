# Plan: Accurate Executable CLI Usage
*Distilled: 2026-08-16*

## Summary

Make the root README's commands match the implemented interfaces and make its direct
`./script.py` examples executable. Document the small set of final behavior contracts
from the preceding plans without adding packaging, CI, or a separate manual.

## Problem

Every scanner example uses the removed `--targets` option, two misspell
`--target-threads`, and all three shebang-based scripts are tracked as mode `0644`, so
the documented direct invocations fail. The README also omits current concurrency and
share-filter options and does not describe the revised status/output behavior.

## Scope

In scope:

- Correct scanner examples to use positional targets and valid option spellings.
- Briefly document `--dir-threads`, `--exclude-shares`, scanner/downloader exit status,
  analyzer terminal-only color, and digest-suffixed download names.
- Prefer password prompting in examples and note the exposure risk of command-line
  passwords.
- Mark `share_sniffer.py`, `analyze.py`, and `downloader.py` executable in Git.
- Document the single `unittest` discovery command for the compact regression suite.

Out of scope:

- CLI compatibility aliases or new options.
- Code cleanup, formatting, type hints, or module decomposition.
- CI, coverage targets, external test tooling, packaging/release/version machinery,
  dependency locking, or a license choice.

## Design

Treat each parser's `--help` output as the implemented option contract and keep
`README.md` as the sole user guide. Show minimal working commands first, retain the
existing concise authentication flag list, and add short notes for concurrency,
machine-safe analyzer result paths, exit status, and deterministic download naming.
Keep direct `./...` commands and record executable bits for all three entry points so
those examples are true. Do not add configuration or documentation files.

This plan follows the four behavior plans so its wording describes their final
contracts. It does not own or alter those behaviors.

## Affected Components

- `README.md`: correct commands and document the final user-facing contracts.
- `share_sniffer.py`: executable mode only.
- `analyze.py`: executable mode only.
- `downloader.py`: executable mode only.

## Implementation Sequence

1. Complete the preceding behavior plans.
2. Update README commands and concise behavior/security/testing notes.
3. Record executable modes on all three scripts.
4. Compare every documented option and invocation against parser help.

## Validation

- Run `./share_sniffer.py --help`, `./analyze.py --help`, and
  `./downloader.py --help` successfully.
- Run `python3 -m unittest discover -v`.
- Run `git diff --check` and compare README option spelling with all three help screens.

## Success Criteria

- Every README command parses and its direct script invocation is executable.
- Current options and the four revised behavior contracts are documented concisely.
- Credential examples favor prompting and warn about command-line secret exposure.
- The project remains a simple script collection without added infrastructure.
