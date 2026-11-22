#!/usr/bin/env python3
"""Copies static/schemas/**/*.json into ../packages/lib/schemas/, preserving
the same relative layout so their $refs resolve identically over HTTP.

WS-3.2 (audit, 2026-11-21): this used to copy the other way (lib -> static).
packages/lib/schemas had drifted stale at the time (still required fields
the proof-model rewrite had already retired) while static/schemas had been
hand-fixed to match -- running the sync in that direction would have
silently reverted the live, correct schemas back to the stale ones. static/
schemas is the schemas' own source of truth going forward; edit there
first, then run this to copy the result into packages/lib/schemas (kept
byte-identical, enforced by packages/lib/tests/schemas.test.ts).

Run after editing any schema, before building."""
import glob
import os
import shutil

SRC_ROOT = 'static/schemas'
DEST_ROOT = '../packages/lib/schemas'

def main():
    for src in glob.glob(os.path.join(SRC_ROOT, '**/*.json'), recursive=True):
        rel = os.path.relpath(src, SRC_ROOT)
        dest = os.path.join(DEST_ROOT, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(src, dest)
        print(f'{src} -> {dest}')

if __name__ == '__main__':
    main()
