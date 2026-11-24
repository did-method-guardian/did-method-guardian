// Regression test for the migration-ordering bug found applying 0013
// to a real, already-populated remote D1 for the first time: D1's
// remote engine enforces foreign keys strictly, including the
// implicit DELETE a DROP TABLE performs against a parent row other
// tables' FKs still reference -- wrangler's own `--local` dev
// emulation does not enforce this at all, so it stayed invisible
// through every other test in this repo. Plain sqlite3, with
// `PRAGMA foreign_keys = ON` and real rows present (not just an
// empty schema), is what actually catches this class of bug, so
// that's what's used here instead of wrangler/D1.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

const MIGRATIONS_DIR = path.resolve(import.meta.dirname, "..", "migrations");

function migrationFiles(): string[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();
}

function applyMigrations(dbPath: string, files: string[]): void {
  const sql = files.map((f) => readFileSync(path.join(MIGRATIONS_DIR, f), "utf8")).join("\n");
  execFileSync("sqlite3", ["-bail", dbPath, `PRAGMA foreign_keys = ON;\n${sql}`], { stdio: "pipe" });
}

function withScratchDb(name: string, run: (dbPath: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), `guardian-migrations-${name}-`));
  try {
    run(path.join(dir, "db.sqlite3"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("every migration applies cleanly from an empty database, with foreign keys enforced", () => {
  withScratchDb("fresh", (dbPath) => {
    assert.doesNotThrow(() => applyMigrations(dbPath, migrationFiles()));
  });
});

test("every migration applies cleanly on top of the pre-reset schema (0001-0012) that an already-deployed, already-used registrar actually has live -- WITH real rows present, foreign keys enforced", () => {
  withScratchDb("upgrade", (dbPath) => {
    const files = migrationFiles();
    const preReset = files.filter((f) => f < "0013");
    const reset = files.filter((f) => f >= "0013");
    applyMigrations(dbPath, preReset);

    // The exact detail that made this invisible everywhere else this
    // was tested: an empty pre-reset schema has nothing for 0013's
    // own DROP TABLE statements to cascade-check against, so the bug
    // only shows up once there's at least one real row in a table
    // another table's FK points to (DROP TABLE performs an implicit
    // DELETE under foreign_keys=ON, and that delete is checked like
    // any other).
    execFileSync(
      "sqlite3",
      [
        "-bail",
        dbPath,
        [
          "PRAGMA foreign_keys = ON;",
          "INSERT INTO wards (name, did, public_key, private_key_enc, created_at) VALUES ('_', 'did:guardian:example.test', 'pk', 'ct', '2026-01-01');",
          "INSERT INTO operations (cid, did, prev_cid, op_type, payload, created_at) VALUES ('cid1', 'did:guardian:example.test', NULL, 'create', '{}', '2026-01-01');",
        ].join("\n"),
      ],
      { stdio: "pipe" },
    );

    assert.doesNotThrow(() => applyMigrations(dbPath, reset));
  });
});
