#!/usr/bin/env python3
"""Strips Chroma's `<span class="ln">N</span>` line-number markup from every
built page's code blocks. hyperctl's syntax highlighter emits these for
".bash"/".json"/etc fenced blocks; the theme's own CSS was never written to
hide them, so they render as literal text otherwise. Run after every
`hyperctl build complete`, before deploying -- this used to be a one-off
inline snippet run by hand, which is exactly why it kept getting skipped."""
import re
import glob
import os
import sys

BUILD_DIR = sys.argv[1] if len(sys.argv) > 1 else 'builds/current'
PATTERN = re.compile(r'<span class="ln">\s*\d+</span>')

def main():
    changed = 0
    for path in glob.glob(os.path.join(BUILD_DIR, '**', '*.html'), recursive=True):
        with open(path, encoding='utf-8') as f:
            content = f.read()
        if 'class="ln"' not in content:
            continue
        with open(path, 'w', encoding='utf-8') as f:
            f.write(PATTERN.sub('', content))
        changed += 1
    print(f'stripped line-number spans from {changed} file(s) under {BUILD_DIR}')

if __name__ == '__main__':
    main()
