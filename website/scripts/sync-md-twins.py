#!/usr/bin/env python3
"""Copies every docs page's raw Markdown source into static/ at the same
path (.md extension), so each is served as a static file twin alongside its
rendered HTML -- e.g. content/docs/index.md -> static/docs/index.md ->
/docs/index.md. Run after editing any docs page, before building."""
import glob
import os
import shutil

SRC_ROOT = 'content/docs'
DEST_ROOT = 'static/docs'

def main():
    for src in glob.glob(os.path.join(SRC_ROOT, '**/index.md'), recursive=True):
        rel = os.path.relpath(src, SRC_ROOT)
        dest = os.path.join(DEST_ROOT, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(src, dest)
        print(f'{src} -> {dest}')

if __name__ == '__main__':
    main()
