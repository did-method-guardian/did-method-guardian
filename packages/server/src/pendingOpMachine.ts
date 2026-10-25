// A pure, synchronous description of a pending multi-signer operation's own
// lifecycle (proposed -> collecting -> satisfied -> finalized, with expired
// and declined as terminal alternatives) -- deliberately free of any async
// I/O (no crypto verification, no D1, no network) so it's fully testable via
// xstate/graph's own path generation (pendingOpMachine.test.ts). All real
// work -- verifying a signature, deciding whether a threshold is now met,
// persisting a row, calling submitOperation -- happens in pendingOps.ts,
// which computes the answer first and feeds it into this machine as plain
// event data (e.g. `satisfiedNow`), never as a guard that itself performs
// that work.

import { assign, createMachine } from "xstate";
import type { Did } from "@did-guardian/lib";

export interface PendingOpContext {
  collectedSigs: Record<Did, string>;
  /** Decided once, before the actor is created -- whether the proposer's own first signature already satisfies the operation's own rule. */
  satisfiedAtPropose: boolean;
}

export type PendingOpEvent =
  | { type: "CONTRIBUTE"; did: Did; sig: string; satisfiedNow: boolean }
  /** Veto -- any current guardian, whether or not they'd already signed, unconditionally kills the proposal. Allowed from `collecting` or `satisfied`: anything short of actually reaching the log is still reversible. */
  | { type: "DECLINE" }
  /** Opt-out -- "don't wait on me." Never blocks; only valid from `collecting`, since once satisfied nobody's waiting on anyone. Removes the withdrawing party's own signature from consideration if they'd already contributed one. */
  | { type: "WITHDRAW"; did: Did }
  | { type: "EXPIRE" }
  | { type: "FINALIZED" }
  | { type: "FINALIZE_FAILED" };

export const pendingOperationMachine = createMachine({
  types: {} as {
    context: PendingOpContext;
    events: PendingOpEvent;
    input: PendingOpContext;
  },
  id: "pendingOperation",
  context: ({ input }) => input,
  initial: "proposed",
  states: {
    // Transient -- exits immediately, before any event can arrive. Exists so
    // a proposal whose first signer already satisfies the rule alone (e.g. a
    // 1-of-N threshold) skips collecting entirely, rather than sitting in a
    // "waiting for more signers" state that will never get any.
    proposed: {
      always: [
        { target: "satisfied", guard: ({ context }) => context.satisfiedAtPropose },
        { target: "collecting" },
      ],
    },
    collecting: {
      on: {
        CONTRIBUTE: [
          {
            target: "satisfied",
            guard: ({ event }) => event.satisfiedNow,
            actions: assign({
              collectedSigs: ({ context, event }) => ({ ...context.collectedSigs, [event.did]: event.sig }),
            }),
          },
          {
            target: "collecting",
            actions: assign({
              collectedSigs: ({ context, event }) => ({ ...context.collectedSigs, [event.did]: event.sig }),
            }),
          },
        ],
        DECLINE: { target: "declined" },
        WITHDRAW: {
          target: "collecting",
          actions: assign({
            collectedSigs: ({ context, event }) => {
              const { [event.did]: _removed, ...rest } = context.collectedSigs;
              return rest;
            },
          }),
        },
        EXPIRE: { target: "expired" },
      },
    },
    satisfied: {
      on: {
        FINALIZED: { target: "finalized" },
        // Retriable -- e.g. the ward's log head moved between reaching
        // `satisfied` and actually calling submitOperation. Stays put rather
        // than dead-ending, since the signatures already collected are
        // still valid; only the attempt to append failed.
        FINALIZE_FAILED: { target: "satisfied" },
        // A guardian can still veto right up until something is actually
        // irreversible -- `satisfied` isn't that yet (it's usually followed
        // synchronously by finalization in the same request, but the retry
        // window above means it can sit here for real).
        DECLINE: { target: "declined" },
      },
    },
    finalized: { type: "final" },
    declined: { type: "final" },
    expired: { type: "final" },
  },
});
