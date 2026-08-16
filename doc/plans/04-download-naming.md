# Plan: Collision-Resistant Download Names
*Distilled: 2026-08-16*

## Summary

Derive each flat local download filename from the canonical UNC identity before
sanitizing it. Retain a readable bounded prefix and append a deterministic SHA-256
digest so distinct remote paths no longer collide through separator replacement.

## Problem

The downloader replaces remote separators with underscores and then sanitizes the
result. Distinct paths such as `//host/share/a/b.txt` and
`//host/share/a_b.txt` consequently target the same local file, allowing the later
download to overwrite the first. Including an entire flattened remote path can also
exceed a filesystem's filename-component limit.

## Scope

In scope:

- Normalize remote separators and construct identity from parsed host, share, and
  remote path, excluding inline credentials.
- Generate a stable flat filename with a readable sanitized prefix plus a full SHA-256
  digest of that canonical identity.
- Bound the ASCII filename component to at most 240 bytes.
- Preserve `.part` download and atomic replacement behavior.
- Add pure naming regressions.

Out of scope:

- Recreating the remote directory tree, a download manifest, or migration of old local
  filenames.
- Cryptographic authenticity guarantees; the digest is only a deterministic identity
  suffix.
- Other download or authentication behavior.

## Design

Replace the current one-argument sanitizer with a focused filename function that takes
parsed `host`, `share`, and `remote`. Normalize backslashes to forward slashes and strip
leading remote separators, then form `//host/share/remote` for hashing. Sanitize that
same identity to an ASCII readable prefix, trim leading punctuation, and fall back to a
neutral prefix if none remains. Truncate the prefix so the separator plus the full
64-character hexadecimal SHA-256 digest keeps the resulting component at or below 240
bytes. Use the returned component directly under the existing output directory.

Identical canonical identities must return the same name. Slash and backslash spellings
of the same remote path must also agree, while identities that only collide after
sanitization must differ.

## Affected Components

- `downloader.py`: own canonicalization and bounded digest-based local naming.
- `tests/test_regressions.py`: add pure naming invariants.

## Implementation Sequence

1. Replace the current sanitizer with canonical identity and bounded digest naming.
2. Use the helper for each local and `.part` path without changing transfer behavior.
3. Add determinism, separator normalization, collision, and length regressions.

## Validation

- Run `python3 -m unittest -v tests.test_regressions.DownloadNamingTests`.
- Run `python3 -m compileall -q downloader.py tests`.
- Verify `a/b.txt` and `a_b.txt` produce different names, slash variants of the same
  path agree, and very long input remains at most 240 ASCII bytes.

## Success Criteria

- Distinct canonical UNC identities do not collide merely because unsafe characters or
  separators sanitize to underscores.
- Repeated equivalent input maps to the same local filename.
- Generated components are flat, readable, deterministic, and no longer than 240
  bytes.
- No runtime or test dependency is added.
