#!/usr/bin/env python3
"""Copies every docs page's raw Markdown source into static/ at the same
path (.md extension), so each is served as a static file twin alongside its
rendered HTML -- e.g. content/docs/index.md -> static/docs/index.md ->
/docs/index.md. Also regenerates src/index.ts's MARKDOWN_TWIN_PATHS list
(WS-6.2, audit) between its own BEGIN/END markers, so that set can never
drift from the actual content tree the way a hand-maintained list would.
Run after editing any docs page (or adding/removing one), before building."""
import glob
import os
import re
import shutil

SRC_ROOT = 'content/docs'
DEST_ROOT = 'static/docs'
WORKER_SRC = 'src/index.ts'
BEGIN_RE = re.compile(r'^[ \t]*// MARKDOWN_TWIN_PATHS:BEGIN[ \t]*$', re.MULTILINE)
END_RE = re.compile(r'^[ \t]*// MARKDOWN_TWIN_PATHS:END[ \t]*$', re.MULTILINE)

def url_path_for(src: str) -> str:
    rel = os.path.relpath(src, SRC_ROOT)
    # content/docs/index.md -> /docs/ ; content/docs/foo/index.md -> /docs/foo/
    rel_dir = os.path.dirname(rel)
    return '/docs/' + (rel_dir + '/' if rel_dir else '')

def main():
    pages = sorted(glob.glob(os.path.join(SRC_ROOT, '**/index.md'), recursive=True))
    for src in pages:
        rel = os.path.relpath(src, SRC_ROOT)
        dest = os.path.join(DEST_ROOT, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(src, dest)
        print(f'{src} -> {dest}')

    with open(WORKER_SRC, 'r') as f:
        worker_src = f.read()
    begin_matches = list(BEGIN_RE.finditer(worker_src))
    end_matches = list(END_RE.finditer(worker_src))
    if len(begin_matches) != 1 or len(end_matches) != 1:
        raise SystemExit(
            f'{WORKER_SRC}: expected exactly one MARKDOWN_TWIN_PATHS BEGIN/END marker pair, '
            f'found {len(begin_matches)} BEGIN and {len(end_matches)} END'
        )
    begin_line_start, begin_line_end = begin_matches[0].span()
    end_line_start, end_line_end = end_matches[0].span()
    if end_line_start <= begin_line_end:
        raise SystemExit(f'{WORKER_SRC}: END marker must come after BEGIN')
    paths = sorted(url_path_for(src) for src in pages)
    block = '\n'.join(f'  "{p}",' for p in paths)
    new_worker_src = worker_src[:begin_line_end] + '\n' + block + worker_src[end_line_start - 1:]
    # The slice above keeps BEGIN's own line and END's own line untouched,
    # replacing only everything strictly between them.
    if new_worker_src != worker_src:
        with open(WORKER_SRC, 'w') as f:
            f.write(new_worker_src)
        print(f'{WORKER_SRC}: regenerated MARKDOWN_TWIN_PATHS ({len(paths)} paths)')

if __name__ == '__main__':
    main()
