#!/usr/bin/env python3
"""Regenerates static/llms-full.txt from the actual docs markdown sources.
Run this after editing any of content/docs/**/index.md, before building."""
import re

def strip_frontmatter(text):
    m = re.match(r'^---\n.*?\n---\n', text, re.DOTALL)
    return text[m.end():].lstrip('\n') if m else text

FILES = [
    ('Guide', 'content/docs/index.md', 'https://guardianspec.org/docs/'),
    ('Formal specification', 'content/docs/did-guardian-spec-v0.2.0/index.md', 'https://guardianspec.org/docs/did-guardian-spec-v0.2.0/'),
    ('Registrar API', 'content/docs/registrar/index.md', 'https://guardianspec.org/docs/registrar/'),
]

def main():
    parts = ['# did:guardian -- full text\n']
    parts.append(
        "This file concatenates the three documents that make up did:guardian's "
        "own documentation, in full, for a single-fetch read. Each section below "
        "corresponds to one live page; the canonical URL for each is given in its "
        "own heading.\n"
    )
    for title, path, url in FILES:
        raw = open(path, encoding='utf-8').read()
        body = strip_frontmatter(raw)
        parts.append(f'\n\n---\n\n# {title}\n\nCanonical URL: {url}\n\n{body.strip()}\n')
    out = ''.join(parts)
    open('static/llms-full.txt', 'w', encoding='utf-8').write(out)
    print(f'wrote static/llms-full.txt ({len(out.split())} words)')

if __name__ == '__main__':
    main()
