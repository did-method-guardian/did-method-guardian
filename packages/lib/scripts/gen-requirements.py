#!/usr/bin/env python3
"""Generates requirements.json: every REQ id in the formal spec, with its
section, text, and which test files (by name match, not guesswork) mention
it by id. Run from the repo root. Regenerate after editing the spec or
adding/renaming a test that references a REQ id."""
import re
import json
import glob
import os

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..', '..', '..')
SPEC_PATH = os.path.join(REPO_ROOT, 'website/content/docs/did-guardian-spec-v0.2.0/index.md')
TEST_GLOBS = [
    'packages/lib/tests/*.test.ts',
    'packages/server/tests/*.test.ts',
]

def extract_requirements(spec_text):
    section = None
    subsection = None
    reqs = []
    # The optional `(?:\s*\([^)]*\))?` handles a parenthetical label between
    # the bolded id and its colon, e.g. "**REQ-6-8** (nullification): ..." --
    # missing this dropped REQ-6-8/REQ-6-9 silently until caught by REQ-12-2
    # using the same pattern.
    req_pattern = re.compile(r'<a id="(req-[\d.a-z-]+)"></a>\*\*(REQ-[\d.A-Za-z-]+)\*\*(?:\s*\([^)]*\))?:\s*(.*)')
    for line in spec_text.split('\n'):
        h2 = re.match(r'^## (\d+)\. (.+)', line)
        h3 = re.match(r'^### ([\d.]+) (.+)', line)
        if h2:
            section, subsection = f'{h2.group(1)}. {h2.group(2)}', None
            continue
        if h3:
            subsection = f'{h3.group(1)} {h3.group(2)}'
            continue
        m = req_pattern.search(line)
        if m:
            anchor, req_id, text = m.groups()
            reqs.append({
                'id': req_id,
                'anchor': f'https://guardianspec.org/docs/did-guardian-spec-v0.2.0/#{anchor}',
                'section': subsection or section,
                'text': text.strip(),
            })
    return reqs

def find_test_coverage(repo_root):
    """Maps each REQ id (bare id, e.g. REQ-7.2-7a) found in a test file's
    own test-name strings to the file it appears in. Not full static
    coverage analysis -- a textual match on test names, which this
    project's own test suite already names by REQ id consistently."""
    coverage = {}
    req_mention = re.compile(r'REQ-\d+(?:\.\d+)?-\d+[a-z]?(?:\([ab]\))?')
    for pattern in TEST_GLOBS:
        for path in glob.glob(os.path.join(repo_root, pattern)):
            text = open(path, encoding='utf-8').read()
            rel = os.path.relpath(path, repo_root)
            for m in req_mention.finditer(text):
                raw = m.group(0)
                base_id = re.sub(r'\(([ab])\)', r'\1', raw)  # "REQ-7.2-7(a)" -> "REQ-7.2-7a"
                coverage.setdefault(base_id, set()).add(rel)
    return {k: sorted(v) for k, v in coverage.items()}

def main():
    spec_text = open(SPEC_PATH, encoding='utf-8').read()
    reqs = extract_requirements(spec_text)
    coverage = find_test_coverage(REPO_ROOT)
    for r in reqs:
        r['tests'] = coverage.get(r['id'], [])
    out_path = os.path.join(REPO_ROOT, 'website/static/requirements.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({'requirements': reqs, 'count': len(reqs)}, f, indent=2)
        f.write('\n')
    covered = sum(1 for r in reqs if r['tests'])
    print(f'wrote {out_path}: {len(reqs)} requirements, {covered} with test-name matches')

if __name__ == '__main__':
    main()
