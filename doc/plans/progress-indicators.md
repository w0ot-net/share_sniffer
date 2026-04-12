# Plan: Progress Indicators for Share Enumeration

## Summary

Add periodic progress lines to `write_tree()` so the user can see enumeration is still
active during long-running share scans.  The indicator works identically regardless of
which threading flags are in use (`--target-threads`, `--share-threads`, `--dir-threads`).

## Problem

Once `write_tree()` begins enumerating a large share, the only output is the initial
`[+] host: SHARE -> path` line.  There is no further feedback until enumeration finishes,
which can take minutes or longer.  The user cannot distinguish a stuck process from a slow
one.

## Goal

While a share is being enumerated, periodic lines like
`[*] 10.0.1.13: Archive -- 12,847 entries...` appear on stderr every N seconds
(default ~5 s).  No new dependencies.  No change to final output or files.txt content.

## Design

### Pass a label into `write_tree()`

`write_tree()` currently has no knowledge of the host or share context for display
purposes.  Add a `label` parameter (e.g. `"10.0.1.13: Archive"`) that the caller
constructs.  The caller already has `host` and `share_name` in scope at the call site
(line 341).

### Entry counter + monotonic clock check

Introduce two locals at the top of `write_tree()`:

```python
import time
_count = 0
_last_report = time.monotonic()
```

Define a small nested helper:

```python
def _tick():
    nonlocal _count, _last_report
    _count += 1
    now = time.monotonic()
    if now - _last_report >= 5.0:
        print(f"[*] {label} -- {_count:,} entries...", file=sys.stderr)
        _last_report = now
```

### Single-threaded path (lines 82-101)

Call `_tick()` once per entry written inside `walk()`, right after the `handle.write()`
calls (both the directory and file branches).

### Multi-threaded path (lines 103-185)

The counter must be thread-safe.  Replace the plain `_count` with a
`threading.Lock()`-guarded increment (the `results_lock` already exists and is acquired
on every entry -- piggyback on that critical section).  Call `_tick()` inside the
existing `with results_lock:` blocks in `process_entries()` (lines 121-126).

`_tick()` acquires no additional lock beyond `results_lock`, so there is no deadlock
risk.

### Completion line

After `write_tree()` finishes (both paths), print a final summary:

```python
print(f"[*] {label} -- {_count:,} entries, done.", file=sys.stderr)
```

This replaces the trailing `...` with `, done.` so the user sees a clear finish signal.

### No new CLI flags

The progress indicator is always on.  Five seconds is short enough to be useful and long
enough to avoid spam.  No flag to disable it -- if someone redirects stderr, the lines
vanish naturally.

## Affected Components

- `share_sniffer.py:write_tree()` (line 74): add `label` parameter, counter, `_tick()` helper, and calls in both code paths.
- `share_sniffer.py:process_share()` (line 341): pass `label=f"{host}: {share_name}"` to `write_tree()`.
