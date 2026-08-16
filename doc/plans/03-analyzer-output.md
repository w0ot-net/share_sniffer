# Plan: Analyzer Output Correctness
*Distilled: 2026-08-16*

## Summary

Keep analyzer result paths raw for matching and sorting, applying color only to a
separate interactive display value. This removes control bytes from redirected results
and restores exact-filename priority without changing keyword rules or adding an output
format.

## Problem

`analyze.py` inserts ANSI escapes into `path` before constructing and sorting the UNC
result. Redirected result lines therefore contain terminal controls. The code also
checks `is_exact_filename_match()` after modifying the filename, so highlighted exact
names such as `.env` lose their intended priority.

## Scope

In scope:

- Keep raw paths and UNC values unchanged for matching, exact-priority calculation,
  sorting, and non-terminal output.
- Preserve red filename highlighting on interactive terminals.
- Add focused regressions for redirected output and exact ordering.

Out of scope:

- Changes to keyword lists, ignore semantics, scoring, or result-file discovery.
- JSON/CSV output, color flags, content inspection, or analyzer-wide matching cleanup.
- Making the analyzer output as a whole a downloader manifest; access-report lines
  retain their existing role.

## Design

Compute `exact_match` from the original filename before any call to
`highlight_filename()`. Build and retain a raw UNC value for the result tuple and its
sort key. Determine terminal color capability with `sys.stdout.isatty()`; only when it
is true, build a separate display UNC containing the highlighted filename. Print the
raw UNC when stdout is redirected. Keep the existing matching helpers and priority
rules otherwise unchanged.

Use a temporary results tree and captured stdout in `unittest`. A non-TTY capture must
contain no `\x1b` bytes, and an exact file such as `.env` must sort in the existing
high-priority group. A small TTY-like capture verifies that interactive highlighting
still occurs.

## Affected Components

- `analyze.py`: separate raw result state from terminal rendering and compute priority
  before rendering.
- `tests/test_regressions.py`: add analyzer output and priority regressions.

## Implementation Sequence

1. Compute matching, exact priority, and the raw UNC before rendering.
2. Store/sort by the raw value and render a separate value only for TTY stdout.
3. Add redirected, exact-priority, and interactive-color regressions.

## Validation

- Run `python3 -m unittest -v tests.test_regressions.AnalyzerOutputTests`.
- Run `python3 -m compileall -q analyze.py tests`.
- Capture non-TTY analyzer output from a representative `files.txt` and verify it has no
  ANSI escape bytes.

## Success Criteria

- Redirected result paths contain raw UNC text without terminal controls.
- Exact filenames are prioritized from their unmodified values.
- Interactive output retains red filename highlighting.
- Existing match, ignore, and sorting rules otherwise remain unchanged.
