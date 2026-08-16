# Plan: Scanner Failure Reliability
*Distilled: 2026-08-16*

## Summary

Make parallel share enumeration terminate predictably and make total scan failure
visible through the scanner's exit status. Preserve the tool's current best-effort
treatment of inaccessible shares and directories, using simple boolean results rather
than a new result or retry framework.

## Problem

`write_tree()` enqueues directories, starts workers whose SMB connection setup may
raise, and then waits unconditionally on `work_queue.join()`. If every worker exits
before consuming work, the scan hangs permanently. Target and share failures are also
printed and discarded, so `main()` returns `0` even when no target is scanned.

## Scope

In scope:

- Prevent worker connection and directory-operation failures from stranding queued
  work.
- Preserve partial listings and the existing handling of per-directory `SessionError`
  as a skipped inaccessible subtree.
- Return nonzero when no requested target produces a successful share enumeration.
- Add focused mocked regression tests without requiring an SMB server.

Out of scope:

- Retries, reconnects, timeout changes, structured logging, or a general result model.
- Making every inaccessible share or subtree fatal to a best-effort scan.
- Changing scan output layout or concurrency options.

## Design

In parallel mode, establish worker connections and successfully start at least one
worker before enqueueing directories or entering a blocking queue join. Report
connection/thread startup failures and return failure without queueing work if no worker
starts. When `initial_entries` is supplied, process those root entries into accumulated
results and a local subdirectory list, but do not enqueue the subdirectories until a
worker has started. Close connections assigned to threads that do not start. Each
running worker must catch `SessionError` and unexpected exceptions per queue item, call
`task_done()` in all item paths, and continue draining work. A per-directory
`SessionError` remains a best-effort skip; record unexpected exceptions in a
`threading.Event` shared with the caller. Apply the same unexpected error accounting to
root-entry processing, and put worker signaling/joining in cleanup that closes every
established connection even when root processing fails. Write all accumulated results
in the existing sorted order before returning either success or failure, so a failed
parallel traversal does not discard entries already obtained.

Return a boolean from `write_tree()`, `process_share()`, and `process_target()`. A share
is successful when its root is readable, the parallel worker pool (when requested) can
run, and no unexpected traversal error occurs. A target is successful when at least one
share succeeds. Collect those values in both sequential and executor paths; `main()`
returns `0` when at least one target succeeds and `1` when all fail. Print the existing
`done` completion line only for successful traversal; failures must not be labeled done.

## Affected Components

- `share_sniffer.py`: make the queue failure-safe and propagate traversal, share, and
  target status to `main()`.
- `tests/test_regressions.py`: cover all-worker connection failure, per-item unexpected
  failure, and total scanner failure.

## Implementation Sequence

1. Make worker setup and queue processing drain safely and return traversal status.
2. Propagate booleans through share, target, sequential, and executor call paths.
3. Derive the process status from whether any target succeeded.
4. Add bounded mocked regressions for the reproduced hang and exit status.

## Validation

- Run `python3 -m unittest -v tests.test_regressions.ScannerReliabilityTests`.
- Run `python3 -m compileall -q share_sniffer.py tests`.
- Confirm an all-worker connection failure returns within a short test deadline rather
  than hanging, and that an all-target failure returns `1`.

## Success Criteria

- Worker startup or directory processing cannot leave `work_queue.join()` blocked
  indefinitely.
- Best-effort directory access behavior and partial listings are preserved.
- Total scan failure returns nonzero; at least one successfully enumerated target keeps
  the scanner successful.
- The regressions run without network access or a new dependency.
