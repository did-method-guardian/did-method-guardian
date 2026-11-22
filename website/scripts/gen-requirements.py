#!/usr/bin/env python3
"""Regenerates static/requirements.json by extracting every REQ-X-Y from the
formal spec markdown directly, instead of hand-maintaining a parallel copy
that drifts whenever the spec's own section numbers or wording change (as
the pre-reset version had, silently, for most of a full method-wide rewrite).

Run after editing the spec, before building."""
import glob
import json
import os
import re

SPEC_PATH = 'content/docs/did-guardian-spec-v0.2.0/index.md'
OUT_PATH = 'static/requirements.json'
BASE_URL = 'https://guardianspec.org/docs/did-guardian-spec-v0.2.0/'
TEST_GLOBS = ['../packages/*/tests/*.test.ts']

HEADING_RE = re.compile(r'^(#{2,3})\s+(.*)$')
REQ_RE = re.compile(r'<a id="(req-\d+-\d+)"></a>\*\*(REQ-\d+-\d+)\.\*\*\s*(.*)$')


def load_test_files():
    paths = []
    for pattern in TEST_GLOBS:
        paths.extend(sorted(glob.glob(pattern)))
    contents = {}
    for p in paths:
        with open(p) as f:
            contents[os.path.relpath(p, '..')] = f.read()
    return contents


def main():
    with open(SPEC_PATH) as f:
        lines = f.read().splitlines()

    test_files = load_test_files()
    section = None
    reqs = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = HEADING_RE.match(line)
        if m and m.group(2).strip().lower() != 'changelog':
            section = m.group(2).strip()
        m = REQ_RE.match(line)
        if m:
            req_anchor, req_id, rest = m.groups()
            text_lines = [rest]
            j = i + 1
            while j < len(lines) and lines[j].strip() != '':
                text_lines.append(lines[j])
                j += 1
            text = ' '.join(t.strip() for t in text_lines).strip()
            tests = [path for path, content in test_files.items() if req_id in content]
            reqs.append({
                'id': req_id,
                'anchor': BASE_URL + '#' + req_anchor,
                'section': section,
                'text': text,
                'tests': tests,
            })
        i += 1

    with open(OUT_PATH, 'w') as f:
        json.dump({'requirements': reqs}, f, indent=2)
        f.write('\n')
    print(f'{len(reqs)} requirements -> {OUT_PATH}')


if __name__ == '__main__':
    main()
