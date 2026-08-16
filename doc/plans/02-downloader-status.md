# Plan: Downloader Failure Status
*Distilled: 2026-08-16*

## Summary

Make the downloader's process status reflect the explicitly requested transfers. Keep
its current continue-on-error behavior and messages, adding only one aggregate failure
flag and focused mocked tests.

## Problem

Connection and transfer exceptions set a local display status or skip a host, but their
outcome never reaches `main()`. The downloader therefore returns `0` after partial or
complete failure, which prevents scripts from detecting missed files.

## Scope

In scope:

- Return nonzero if any requested host connection or file transfer fails.
- Continue processing remaining hosts and files after a failure.
- Preserve successful downloads, `.part` cleanup, and existing status messages.
- Add focused mocked regression tests.

Out of scope:

- Fail-fast behavior, retries, summaries, new exit-code categories, or logging changes.
- Download filename changes, which are owned by the download-naming plan.
- Live SMB integration tests.

## Design

Initialize a single aggregate success flag after argument validation. Mark it failed
when a grouped host connection cannot be established or a requested `getFile()` does
not complete. Do not reset it after later successes. Preserve the existing loops so all
remaining work is attempted, then return `0` only when every requested transfer
succeeded and `1` otherwise. Input/authentication validation continues to return early
as it does now.

Use fake connections in `unittest` to cover complete failure, mixed success/failure,
and all-success behavior. Tests should assert the returned status and continued
attempts, not internal flag structure.

## Affected Components

- `downloader.py`: aggregate connection and transfer outcomes into the final status.
- `tests/test_regressions.py`: add downloader status regressions.

## Implementation Sequence

1. Track connection and transfer failures without changing loop control.
2. Derive the final return value from the aggregate outcome.
3. Add mocked complete, mixed, and successful transfer cases.

## Validation

- Run `python3 -m unittest -v tests.test_regressions.DownloaderStatusTests`.
- Run `python3 -m compileall -q downloader.py tests`.
- Confirm mixed transfers continue after a failure and still return `1`.

## Success Criteria

- Any failed requested transfer or required host connection makes the process return
  nonzero.
- Later work is still attempted after a failure.
- An all-success invocation returns `0` and retains atomic `.part` replacement.
- Tests require no live server or new dependency.
