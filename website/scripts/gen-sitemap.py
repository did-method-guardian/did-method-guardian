#!/usr/bin/env python3
"""Regenerates static/sitemap.xml from the actual docs markdown sources,
plus the site root. WS-6.2 (audit): this used to be a hand-maintained
list of four URLs, already missing the how-to pages and prior-art by
the time this ran -- generated from content/docs/**/index.md instead,
the same tree scripts/sync-md-twins.py already walks, so a new page can
never be silently missing here. Run after adding or removing a docs
page, before building."""
import glob
import os

SRC_ROOT = 'content/docs'
BASE_URL = 'https://guardianspec.org'
OUT_PATH = 'static/sitemap.xml'

# Priority by depth under content/docs/ (0 = content/docs/index.md itself,
# 1 = a top-level section like registrar/ or how-to/, 2 = a how-to subpage).
PRIORITY_BY_DEPTH = {0: 0.9, 1: 0.8}
DEFAULT_PRIORITY = 0.6

def depth_of(rel_path):
    rel_dir = os.path.dirname(rel_path)
    return 0 if not rel_dir else rel_dir.count(os.sep) + 1

def url_for(rel_path):
    rel_dir = os.path.dirname(rel_path)
    return f'{BASE_URL}/docs/' + (rel_dir + '/' if rel_dir else '')

def main():
    pages = sorted(glob.glob(os.path.join(SRC_ROOT, '**/index.md'), recursive=True))
    rel_paths = sorted(os.path.relpath(p, SRC_ROOT) for p in pages)

    entries = [(f'{BASE_URL}/', 1.0)]
    for rel_path in rel_paths:
        priority = PRIORITY_BY_DEPTH.get(depth_of(rel_path), DEFAULT_PRIORITY)
        entries.append((url_for(rel_path), priority))

    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for loc, priority in entries:
        lines.append('  <url>')
        lines.append(f'    <loc>{loc}</loc>')
        lines.append('    <changefreq>monthly</changefreq>')
        lines.append(f'    <priority>{priority}</priority>')
        lines.append('  </url>')
    lines.append('</urlset>')
    out = '\n'.join(lines) + '\n'
    open(OUT_PATH, 'w', encoding='utf-8').write(out)
    print(f'wrote {OUT_PATH} ({len(entries)} urls)')

if __name__ == '__main__':
    main()
