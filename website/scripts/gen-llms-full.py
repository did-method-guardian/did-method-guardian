#!/usr/bin/env python3
"""Regenerates static/llms-full.txt from the actual docs markdown sources.

WS-6.2 (audit): the page list used to be a hand-maintained FILES constant
(three entries, long after the docs tree grew past three pages) -- it is
now discovered from content/docs/**/index.md itself, the same tree
scripts/sync-md-twins.py already walks, so a new page can never be
silently missing here the way the how-to pages and prior-art previously
were. Run this after editing any of content/docs/**/index.md, before
building.
"""
import glob
import os
import re

SRC_ROOT = 'content/docs'
BASE_URL = 'https://guardianspec.org'

# Reading order for the top-level sections -- everything else (how-to
# subpages) sorts after these, alphabetically by path. Keyed by the page's
# path relative to SRC_ROOT.
ORDER = {
    'index.md': 0,
    'did-guardian-spec-v0.2.0/index.md': 1,
    'registrar/index.md': 2,
    'prior-art/index.md': 3,
    'how-to/index.md': 4,
}

def strip_frontmatter(text):
    m = re.match(r'^---\n(.*?)\n---\n', text, re.DOTALL)
    if not m:
        return {}, text
    fm = {}
    for line in m.group(1).splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            fm[k.strip()] = v.strip().strip('"').strip("'")
    body = text[m.end():].lstrip('\n')
    # Every page already opens with its own `# <Title>` H1 (and sometimes a
    # <script type="application/ld+json"> block before it) -- drop that one
    # leading H1 so it doesn't duplicate the heading this script already
    # generates from frontmatter `title`, right above where body gets
    # inserted.
    body = re.sub(r'^(?:<script[^>]*>.*?</script>\s*\n+)?#[^\n]*\n+', '', body, count=1, flags=re.DOTALL)
    return fm, body

def url_for(rel_path):
    rel_dir = os.path.dirname(rel_path)
    return f'{BASE_URL}/docs/' + (rel_dir + '/' if rel_dir else '')

def sort_key(rel_path):
    return (ORDER.get(rel_path, 99), rel_path)

def main():
    pages = sorted(glob.glob(os.path.join(SRC_ROOT, '**/index.md'), recursive=True))
    rel_paths = sorted((os.path.relpath(p, SRC_ROOT) for p in pages), key=sort_key)

    parts = ['# did:guardian -- full text\n']
    parts.append(
        "This file concatenates every page under /docs/ in full, for a "
        "single-fetch read. Each section below corresponds to one live "
        "page; the canonical URL for each is given in its own heading.\n"
    )
    for rel_path in rel_paths:
        src = os.path.join(SRC_ROOT, rel_path)
        raw = open(src, encoding='utf-8').read()
        fm, body = strip_frontmatter(raw)
        title = fm.get('title', rel_path)
        url = url_for(rel_path)
        parts.append(f'\n\n---\n\n# {title}\n\nCanonical URL: {url}\n\n{body.strip()}\n')
    out = ''.join(parts)
    open('static/llms-full.txt', 'w', encoding='utf-8').write(out)
    print(f'wrote static/llms-full.txt ({len(out.split())} words, {len(rel_paths)} pages)')

if __name__ == '__main__':
    main()
