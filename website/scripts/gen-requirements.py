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
            # WS-M18 (audit): this used to stop at the first blank line,
            # which is also where a REQ's own clarifying table or list
            # starts (REQ-10-1's own resource table, say) -- the real
            # boundary is the next REQ anchor or heading, not the next
            # blank line. Collecting through blank lines keeps a table
            # or list that belongs to this REQ; stopping at the next
            # REQ_RE/HEADING_RE match keeps the next REQ's own text out.
            text_lines = [rest]
            j = i + 1
            while j < len(lines) and not REQ_RE.match(lines[j]) and not HEADING_RE.match(lines[j]):
                text_lines.append(lines[j])
                j += 1
            while text_lines and text_lines[-1].strip() == '':
                text_lines.pop()
            text = '\n'.join(t.rstrip() for t in text_lines).strip('\n')
            # WS-M18 (audit): `req_id in content` is a bare substring
            # check -- "REQ-10-1" is itself a substring of "REQ-10-15"
            # (and REQ-10-10 through REQ-10-19), so a test file citing
            # a different, higher-numbered requirement in the same
            # section falsely credited this one too. Every id already
            # starts at its own word boundary, so only the trailing one
            # needs checking: never followed by another digit.
            id_pattern = re.compile(re.escape(req_id) + r'(?!\d)')
            tests = [path for path, content in test_files.items() if id_pattern.search(content)]
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
