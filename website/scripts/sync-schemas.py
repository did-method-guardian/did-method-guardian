#!/usr/bin/env python3
"""Copies packages/lib/schemas/**/*.json into static/schemas/, preserving
the same relative layout so their $refs resolve identically over HTTP.
Run after editing any schema, before building."""
import glob
import os
import shutil

SRC_ROOT = '../packages/lib/schemas'
DEST_ROOT = 'static/schemas'

def main():
    for src in glob.glob(os.path.join(SRC_ROOT, '**/*.json'), recursive=True):
        rel = os.path.relpath(src, SRC_ROOT)
        dest = os.path.join(DEST_ROOT, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(src, dest)
        print(f'{src} -> {dest}')

if __name__ == '__main__':
    main()
