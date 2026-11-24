-- REQ-10-15 (spec r7/r7b): the anchor and version this registrar last
-- recorded for every log it has fetched under REQ-10-7, across every
-- identity on every domain -- not scoped to this registrar's own
-- domain, since REQ-10-7 fetches guardians and successors hosted
-- anywhere. No FK: a pinned DID is frequently NOT one this registrar
-- hosts a log for at all.
CREATE TABLE pins (
  did TEXT PRIMARY KEY,
  anchor TEXT NOT NULL,
  version TEXT NOT NULL
);
