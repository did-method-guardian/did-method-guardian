#!/usr/bin/env python3
"""Copies each docs page's raw Markdown source into static/ at the same path
(.md extension), so it's served as a static file twin alongside the rendered
HTML -- e.g. content/docs/index.md -> static/docs/index.md -> /docs/index.md.
Run this after editing any docs page, before building."""
import os
import shutil

PAGES = [
    'content/docs/index.md',
    'content/docs/did-guardian-spec-v0.2.0/index.md',
    'content/docs/registrar/index.md',
]

def main():
    for src in PAGES:
        dest = os.path.join('static', src[len('content/'):])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(src, dest)
        print(f'{src} -> {dest}')

if __name__ == '__main__':
    main()
