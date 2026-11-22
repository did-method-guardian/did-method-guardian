"""Final vector generator (vectors-final/). Every invalid vector = a valid base scenario + exactly one mutation.

Kinds: verify (default), registrar (REQ-10-5..10-8), resolve (§11). A mutation is one semantic edit at one
tagged operation (body/specs/post/before hooks), or to the vector itself (vec hook).
"""
import copy, hashlib, json, os, shutil
from cryptography.hazmat.primitives.asymmetric import ec, utils as U
from cryptography.hazmat.primitives import hashes as H
from verifier import MINKEYS, op_hash, sign_jcs, encode_key, apply, b58enc, b58dec, P256_N, MULTIKEY_P256, anchor_of, hash_value

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors-final")
PC = {"type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2019", "proofPurpose": "capabilityInvocation"}
D = "did:guardian:acme.com"
ROOT = D


class Ident:
    def __init__(self, did):
        self.did, self.log, self.states = did, [], []
    state = property(lambda s: s.states[-1])
    head = property(lambda s: op_hash(s.log[-1]))
    anchor = property(lambda s: anchor_of(s.log))


def secured(op):
    return {k: v for k, v in op.items() if k not in ("proof", "attestation")}


class World:
    def __init__(self, mut=None):
        self.ids, self.privs, self.n, self.mut, self.snap = {}, {}, 0, mut or {}, None

    def newkey(self):
        self.n += 1
        priv = ec.derive_private_key(0xBEEF + self.n * 7919, ec.SECP256R1())
        pub = encode_key(priv.public_key())
        self.privs[pub] = priv
        return pub

    def proofs(self, doc, signers):
        out = []
        for s in signers:
            vm, priv = (s[0], s[1]) if isinstance(s, tuple) else (f"did:key:{s}#{s}", self.privs[s])
            p = dict(PC, verificationMethod=vm)
            p["proofValue"] = sign_jcs(priv, doc, p)
            out.append(p)
        return sorted(out, key=lambda p: p["verificationMethod"])          # REQ-5-10

    def push(self, idn, body, signers, tag=None, attest=None):
        m = self.mut if (tag and self.mut.get("tag", "final") == tag) else {}
        if "before" in m: m["before"](self, idn)
        body = dict(body)
        if idn.log and "prev" not in body:
            body["prev"] = idn.head
        orig = copy.deepcopy(body)
        if "body" in m: m["body"](body, self, idn)
        if callable(signers):
            try:
                signers = signers(body)
            except (KeyError, TypeError, IndexError):
                signers = signers(orig)            # the edit removed what the signer list is derived from
        signers = list(dict.fromkeys(signers))
        if "specs" in m: signers = m["specs"](signers, self, idn)
        op = dict(body, proof=self.proofs(secured(body), signers))
        if attest is not None:
            op["attestation"] = attest(op)
        if "post" in m: m["post"](op, self, idn)
        if tag == "final":
            self.snap = {d: copy.deepcopy(i.log) for d, i in self.ids.items() if d != idn.did}
        idn.log.append(op)
        try:
            idn.states.append(apply(op, idn.states[-1] if idn.states else None))
        except Exception:
            idn.states.append(copy.deepcopy(idn.states[-1]) if idn.states else None)
        return op

    def attestation(self, did, root_version=-1, key_index=0):
        root = self.ids.get("did:guardian:" + did.split(":")[2])
        if root is None:
            return None
        vi = root_version if root_version >= 0 else len(root.log) + root_version
        k = root.states[vi]["keys"][key_index]

        def f(op):
            p = dict(PC, verificationMethod=f"{root.did}?versionId={op_hash(root.log[vi])}#key-{key_index}")
            p["proofValue"] = sign_jcs(self.privs[k], secured(op), p)
            return p
        return f

    def create(self, did, nkeys=1, guardians=(), successor=None, policy=None, services=(), aka=(), tag=None, root_version=-1):
        m = self.mut if (tag and self.mut.get("tag", "final") == tag) else {}
        did = m.get("did", did)
        idn = Ident(did)
        body = {"type": "create", "did": did, "keys": [self.newkey() for _ in range(nkeys)], "guardians": list(guardians),
                "successor": successor, "policy": policy if policy is not None else {}, "services": list(services),
                "alsoKnownAs": list(aka), "prev": None}

        def signers(b):
            ks = list(b.get("keys")) if isinstance(b.get("keys"), list) else []
            for e in (b.get("guardians") if isinstance(b.get("guardians"), list) else []) + ([b.get("successor")] if isinstance(b.get("successor"), dict) else []):
                ks += e.get("keys", []) if isinstance(e, dict) else []
            return [k for k in dict.fromkeys(ks) if isinstance(k, str) and k in self.privs]
        is_root = did.count(":") == 2
        self.push(idn, body, signers, tag=tag, attest=None if is_root else self.attestation(did, root_version))
        self.ids[did] = idn
        return idn

    def root(self, domain="acme.com", tag=None):
        return self.create("did:guardian:" + domain, tag=tag)

    def update(self, idn, signers, nkeys=1, tag=None, keys=None):
        keys = keys if keys is not None else [self.newkey() for _ in range(nkeys)]
        body = {"type": "update", "keys": keys, "services": idn.state["services"], "alsoKnownAs": idn.state["alsoKnownAs"]}
        return self.push(idn, body, lambda b: [k for k in dict.fromkeys(b["keys"]) if isinstance(k, str) and k in self.privs] + list(signers), tag=tag)

    def guard(self, g, ward, tag=None, signers=None):
        return self.push(g, {"type": "acceptWard", "ward": {"did": ward.did, "anchor": ward.anchor}}, signers or [K(g)], tag=tag)

    def entry(self, g, ward):
        consent = next(op_hash(o) for o in reversed(g.log) if o["type"] == "acceptWard" and o["ward"]["did"] == ward.did)
        return {"did": g.did, "anchor": g.anchor, "keys": list(g.state["keys"]), "consent": consent}

    def add_guardian(self, ward, g, approvers=None, tag=None):
        self.guard(g, ward)
        e = self.entry(g, ward)
        return self.push(ward, {"type": "addGuardian", "entry": e},
                         lambda b: list(b["entry"]["keys"]) + [K(ward)] + (approvers if approvers is not None else default_membership(ward)), tag=tag)


def K(idn, i=0):
    return idn.state["keys"][i]


def GK(ward, did, i=0):
    """a key of the guardian entry for did in ward's state"""
    return next(e for e in ward.state["guardians"] if e["did"] == did)["keys"][i]


def default_membership(ward):
    gs = ward.state["guardians"]
    n = len(gs)
    need = 0 if n == 0 else max(n // 2 + 1, 2 if n >= 2 else 1)
    return [e["keys"][0] for e in gs[:need]]


def fixture(w, n=0, policy=None, tag=None, successor=False, domain="acme.com", gdomain=None):
    w.root(domain)
    if gdomain and gdomain != domain: w.root(gdomain)
    a = w.create(f"did:guardian:{domain}:alice", policy=policy, tag=tag)
    gs = []
    for i in range(n):
        g = w.create(f"did:guardian:{gdomain or domain}:guard{i}")
        w.add_guardian(a, g)
        gs.append(g)
    if successor:
        s = w.create(f"did:guardian:{domain}:succ")
        w.guard(s, a)
        w.push(a, {"type": "setPolicy", "policy": dict(a.state["policy"], orphan="successor"), "successor": w.entry(s, a)},
               lambda b: [K(a)] + default_membership(a) + list(b["successor"]["keys"]))
    return a, gs


# ============================================================ scenarios
SC = {}


def scenario(name, desc, kinds=("verify",), **extra):
    def deco(f):
        SC[name] = (f, desc, kinds, extra)
        return f
    return deco


@scenario("root", "root identity create (no attestation)")
def _(w):
    return w.root(tag="final")


@scenario("create", "create with one key and attestation", kinds=("verify", "registrar", "resolve"))
def _(w):
    w.root()
    return w.create(D + ":alice", tag="final")


@scenario("create-two-keys", "create with two keys (two proofs)", kinds=("verify", "resolve"))
def _(w):
    w.root()
    return w.create(D + ":alice", nkeys=2, tag="final")


@scenario("create-full", "create with 3 keys, a service and alsoKnownAs (DID document)", doc=True)
def _(w):
    w.root()
    return w.create(D + ":alice", nkeys=3, services=[{"id": "#hub", "type": "Hub", "serviceEndpoint": "https://hub.example/a"}],
                    aka=["https://alice.example"], tag="final")


@scenario("appendix-create", "Appendix A: Alice computes her anchor (it excludes guardians), Bob guards it, Alice's create names Bob",
          kinds=("verify", "registrar", "resolve"), entries=True)
def _(w):
    w.root(); bob = w.create(D + ":bob")
    k = w.newkey()
    pre = {"type": "create", "did": D + ":alice", "keys": [k], "guardians": [], "successor": None, "policy": {},
           "services": [], "alsoKnownAs": [], "prev": None}
    anchor = hash_value({x: v for x, v in pre.items() if x not in ("guardians", "successor")})
    w.push(bob, {"type": "acceptWard", "ward": {"did": D + ":alice", "anchor": anchor}}, [K(bob)])
    a = Ident(D + ":alice")
    e = {"did": bob.did, "anchor": bob.anchor, "keys": list(bob.state["keys"]), "consent": bob.head}
    w.push(a, dict(pre, guardians=[e]), lambda b: [k] + [x for g in b.get("guardians", []) for x in g.get("keys", [])], tag="final",
           attest=w.attestation(a.did))
    w.ids[a.did] = a
    return a


@scenario("update-key", "update by one current key")
def _(w):
    a, _ = fixture(w)
    w.update(a, [K(a)], tag="final")
    return a


@scenario("recovery-N1", "update by the one guardian (recovery majority of 1)", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 1)
    w.update(a, [K(gs[0])], tag="final")
    return a


@scenario("guardian-two-keys", "guardian with two keys approves with its second key (REQ-5-16)")
def _(w):
    w.root(); a = w.create(D + ":alice"); g = w.create(D + ":guard0", nkeys=2)
    w.add_guardian(a, g)
    w.update(a, [g.state["keys"][1]], tag="final")
    return a


@scenario("add-N0", "addGuardian N=0: entry keys + one current key", kinds=("verify", "registrar"))
def _(w):
    a, _ = fixture(w)
    g = w.create(D + ":gina")
    w.add_guardian(a, g, tag="final")
    return a


@scenario("add-N1", "addGuardian N=1: entry keys + current key + 1 guardian", kinds=("verify", "registrar", "resolve"))
def _(w):
    a, gs = fixture(w, 1)
    g = w.create(D + ":gina")
    w.add_guardian(a, g, tag="final")
    return a


@scenario("upd-guardian-self", "Appendix A: Bob rotates, updates his entry with new key + old entry key", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 2)
    b = gs[0]
    old = K(b)
    w.update(b, [old])
    w.push(a, {"type": "updateGuardian", "guardian": b.did, "keys": list(b.state["keys"])}, lambda bd: list(bd["keys"]) + [old], tag="final")
    return a


@scenario("upd-guardian-lost", "guardian lost its key (recovered by its own guardian); the 2 other guardians re-seat it (membership, E=N-1)",
          kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 3)
    b = gs[0]
    h = w.create(D + ":helper"); w.add_guardian(b, h)
    w.update(b, [K(h)])                                          # b's guardian recovers b
    w.push(a, {"type": "updateGuardian", "guardian": b.did, "keys": list(b.state["keys"])},
           lambda bd: list(bd["keys"]) + [K(a), GK(a, gs[1].did)], tag="final")
    return a


@scenario("upd-guardian-lost-N2", "FIXED (R4-2): N=2, guardian lost its key; ward key + the other guardian re-seat it", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 2)
    b = gs[0]
    h = w.create(D + ":helper"); w.add_guardian(b, h)
    w.update(b, [K(h)])
    w.push(a, {"type": "updateGuardian", "guardian": b.did, "keys": list(b.state["keys"])},
           lambda bd: list(bd["keys"]) + [K(a), GK(a, gs[1].did)], tag="final")
    return a


@scenario("upd-guardian-sole", "FIXED (S3-1): ward key alone can no longer re-seat its sole guardian", kinds=("verify",), expect=False)
def _(w):
    a, gs = fixture(w, 1)
    b = gs[0]
    w.update(b, [K(b)])
    w.push(a, {"type": "updateGuardian", "guardian": b.did, "keys": list(b.state["keys"])}, lambda bd: list(bd["keys"]) + [K(a)], tag="final")
    return a


@scenario("remove-self-N2", "guardian removes itself (N=2)", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 2)
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, [GK(a, gs[0].did)], tag="final")
    return a


@scenario("remove-any-N2", "N=2, removal any: the other guardian removes")
def _(w):
    a, gs = fixture(w, 2, {"removal": "any"}, tag="alice")
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, [GK(a, gs[1].did)], tag="final")
    return a


def _evidence(by, n=2, policy=None, signer_self=False):
    def f(w):
        a, gs = fixture(w, n, policy)
        g = gs[0]
        w.push(g, {"type": "deactivate"}, [K(g)])
        if signer_self:
            sig = [GK(a, g.did)]
        else:
            sig = [K(a)] if by == "key" else [GK(a, gs[1].did)]
        w.push(a, {"type": "removeGuardian", "guardian": g.did, "evidence": g.head}, sig, tag="final")
        return a
    return f


SC["remove-evidence-key"] = (_evidence("key"), "remove deactivated guardian with evidence + one key", ("verify", "registrar"), {})
SC["remove-evidence-guardian"] = (_evidence("guardian"), "FIXED (S3-3/4): evidence + one other guardian (no key) no longer suffices", ("verify",), {"expect": False})
SC["orphan-deactivate"] = (_evidence("key", 1), "REQ-6-10 row deactivate: last guardian removed with evidence -> deactivated", ("verify", "registrar"), {"deact": True})
SC["orphan-independent"] = (_evidence("key", 1, {"orphan": "independent"}), "REQ-6-10 row independent: no change", ("verify",), {})


@scenario("remove-successor", "FIXED (S3-2): successor path not available at N=2", expect=False)
def _(w):
    a, gs = fixture(w, 2, successor=True)
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, [K(a), a.state["successor"]["keys"][0]], tag="final")
    return a


@scenario("orphan-successor", "REQ-6-10 row successor: key + successor removes the last guardian; successor promoted", kinds=("verify", "registrar"), promoted=True)
def _(w):
    a, gs = fixture(w, 1, successor=True)
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, [K(a), a.state["successor"]["keys"][0]], tag="final")
    return a


@scenario("setpolicy-N0", "setPolicy N=0 by one key")
def _(w):
    a, _ = fixture(w)
    w.push(a, {"type": "setPolicy", "policy": {"recovery": "all", "maxWards": 3}, "successor": None}, [K(a)], tag="final")
    return a


@scenario("setpolicy-N3", "setPolicy N=3: key + 2 guardians")
def _(w):
    a, gs = fixture(w, 3)
    w.push(a, {"type": "setPolicy", "policy": {"recovery": 3}, "successor": None}, [K(a), GK(a, gs[0].did), GK(a, gs[1].did)], tag="final")
    return a


@scenario("setpolicy-successor", "setPolicy naming a new successor: key + guardian + successor keys", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 1)
    s = w.create(D + ":succ"); w.guard(s, a)
    w.push(a, {"type": "setPolicy", "policy": {"orphan": "successor"}, "successor": w.entry(s, a)},
           lambda b: [K(a), GK(a, gs[0].did)] + list(b["successor"]["keys"]), tag="final")
    return a


@scenario("setpolicy-drop-successor", "setPolicy removes the successor: key + guardian; successor not asked")
def _(w):
    a, gs = fixture(w, 1, successor=True)
    w.push(a, {"type": "setPolicy", "policy": {}, "successor": None}, [K(a), GK(a, gs[0].did)], tag="final")
    return a


@scenario("guard-key", "guard approved by one current key", kinds=("verify", "registrar"))
def _(w):
    a, _ = fixture(w)
    c = w.create(D + ":carol")
    w.guard(a, c, tag="final")
    return a


@scenario("guard-guardians", "guard approved by guardians per recovery (N=1)")
def _(w):
    a, gs = fixture(w, 1)
    c = w.create(D + ":carol")
    w.guard(a, c, tag="final", signers=[GK(a, gs[0].did)])
    return a


@scenario("unguard-key", "unguard approved by one current key")
def _(w):
    a, _ = fixture(w)
    c = w.create(D + ":carol"); w.guard(a, c)
    w.push(a, {"type": "releaseWard", "ward": c.did}, [K(a)], tag="final")
    return a


@scenario("unguard-guardians", "unguard approved by guardians per recovery (N=1)")
def _(w):
    a, gs = fixture(w, 1)
    c = w.create(D + ":carol"); w.guard(a, c)
    w.push(a, {"type": "releaseWard", "ward": c.did}, [GK(a, gs[0].did)], tag="final")
    return a


@scenario("maxwards", "maxWards 2: second guard fills it")
def _(w):
    a, _ = fixture(w, 0, {"maxWards": 2}, tag="alice")
    c, d = w.create(D + ":carol"), w.create(D + ":dave")
    w.guard(a, c)
    w.guard(a, d, tag="final")
    return a


@scenario("maxwards-setpolicy", "two wards, then setPolicy keeps maxWards 2")
def _(w):
    a, _ = fixture(w, 0, {"maxWards": 2})
    c, d = w.create(D + ":carol"), w.create(D + ":dave")
    w.guard(a, c); w.guard(a, d)
    w.push(a, {"type": "setPolicy", "policy": {"maxWards": 2}, "successor": None}, [K(a)], tag="final")
    return a


@scenario("deactivate-N0", "deactivate N=0 by key; DID document @context+id", doc=True)
def _(w):
    a, _ = fixture(w)
    w.push(a, {"type": "deactivate"}, [K(a)], tag="final")
    return a


# ---- Appendix A table, policy variants, deactivation.by
TABLE = {1: (1, 1, None, 1), 2: (2, 2, None, 2), 3: (2, 2, 2, 2), 5: (3, 3, 3, 3)}


def _table(col, n, k, policy=None):
    def f(w):
        a, gs = fixture(w, n, policy)
        gk = [GK(a, g.did) for g in gs]
        if col == "recovery":
            w.update(a, gk[:k], tag="final")
        elif col == "membership":
            ng = w.create(D + ":newg")
            w.add_guardian(a, ng, approvers=gk[:k], tag="final")
        elif col == "removal":
            w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, gk[1:1 + k], tag="final")
        else:
            w.push(a, {"type": "deactivate"}, [K(a)] + gk[:k], tag="final")
        return a
    return f


for n, cols in TABLE.items():
    for col, k in zip(("recovery", "membership", "removal", "deactivation"), cols):
        if k is not None:
            SC[f"table-N{n}-{col}"] = (_table(col, n, k), f"Appendix A N={n} {col}: exactly {k} guardian approvals", ("verify",), {})
for rec, n, k in (("any", 3, 1), ("all", 3, 3), (2, 5, 2), (1, 3, 2)):
    SC[f"recovery-{rec}-N{n}"] = (_table("recovery", n, k, {"recovery": rec}), f"recovery={rec!r}, N={n}: {k} approvals", ("verify",), {})


def _deact(by, wk, wg):
    def f(w):
        a, gs = fixture(w, 3, {"deactivation": {"by": by, "threshold": "majority"}})
        w.push(a, {"type": "deactivate"}, ([K(a)] if wk else []) + ([GK(a, g.did) for g in gs[:2]] if wg else []), tag="final")
        return a
    return f


for by, combos in {"self": [(1, 0)], "guardians": [(0, 1)], "either": [(1, 0), (0, 1)], "both": [(1, 1)]}.items():
    for wk, wg in combos:
        SC[f"deact-{by}-{'k' if wk else ''}{'g' if wg else ''}"] = (_deact(by, wk, wg), f"deactivation.by={by}, key={bool(wk)}, 2/3 guardians={bool(wg)}", ("verify",), {})


# ============================================================ ATTACK scenarios (valid per spec)
SC["ATTACK-sole-guardian-kills-ward"] = (
    _evidence("guardian", 1, {"deactivation": {"by": "self", "threshold": "majority"}}, signer_self=True),
    "FIXED (S3-3): the sole guardian can no longer remove itself with its own evidence", ("verify",), {"expect": False})


@scenario("ATTACK-fake-evidence", "ATTACK: by=guardians; ward key alone + fabricated evidence removes the last guardian -> ward deactivated. "
          "Verifies; only REQ-10-6 (trusted) stops it", kinds=("verify", "registrar"), deact=True)
def _(w):
    a, gs = fixture(w, 1, {"deactivation": {"by": "guardians", "threshold": "majority"}})
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did, "evidence": op_hash(gs[0].log[0])}, [K(a)], tag="final")
    return a


@scenario("ATTACK-one-guardian-fake-evidence", "FIXED (S3-4): a guardian alone can no longer use evidence", expect=False)
def _(w):
    a, gs = fixture(w, 3)
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did, "evidence": op_hash(gs[0].log[0])}, [GK(a, gs[1].did)], tag="final")
    return a


@scenario("ATTACK-mutual-chain", "FIXED (S3-1): the ward key alone can no longer re-seat bob's entry in alice", kinds=("verify",), expect=False)
def _(w):
    w.root(); a = w.create(D + ":alice"); b = w.create(D + ":bob")
    w.add_guardian(a, b); w.add_guardian(b, a)
    thief_alice_key = K(a)
    w.update(b, [GK(b, a.did)])                                  # thief, as bob's guardian, replaces bob's keys
    w.push(a, {"type": "updateGuardian", "guardian": b.did, "keys": list(b.state["keys"])},
           lambda bd: list(bd["keys"]) + [thief_alice_key], tag="final")
    return a


@scenario("ACK-mutual-pair", "ACKNOWLEDGED (§12 Mutual guardians): thief with alice's key recovers bob, alice being bob's only guardian; "
          "honest registrar accepts", kinds=("verify", "registrar"))
def _(w):
    w.root(); a = w.create(D + ":alice"); b = w.create(D + ":bob")
    w.add_guardian(a, b); w.add_guardian(b, a)
    w.update(b, [GK(b, a.did)], tag="final")
    return b


def _succ_takeover(w, final_promote):
    a, gs = fixture(w, 2, successor=True)
    sk = a.state["successor"]["keys"][0]
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, [K(a), sk], tag="final")
    return a
    w.push(a, {"type": "removeGuardian", "guardian": gs[1].did}, [K(a), sk], tag="final" if final_promote else None)
    if not final_promote:
        w.update(a, [a.state["guardians"][0]["keys"][0]], tag="final")
    return a


SC["ATTACK-successor-strip"] = (lambda w: _succ_takeover(w, True), "FIXED (S3-2): successor path refused at N=2", ("verify",), {"expect": False})


@scenario("ATTACK-old-key-self-removal", "FIXED at the registrar (S3-7): old key removes the guardian; verifies, standing rejects it",
          kinds=("verify", "registrar"), reg=False)
def _(w):
    a, gs = fixture(w, 2)
    old = K(gs[0])
    w.update(gs[0], [old])
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did}, [old], tag="final")
    return a


@scenario("ATTACK-old-key-recovery", "LAX-ONLY: retired guardian key recovers the ward; verifies; an honest registrar rejects (standing item 3)",
          kinds=("verify", "registrar"), reg=False)
def _(w):
    a, gs = fixture(w, 1)
    old = K(gs[0])
    w.update(gs[0], [old])
    w.update(a, [old], tag="final")
    return a


@scenario("ATTACK-lax-registrar-guardian-swap", "FIXED (S3-1): ward key alone cannot re-seat even under a lax registrar", kinds=("verify",), expect=False)
def _(w):
    a, gs = fixture(w, 1)
    w.push(a, {"type": "updateGuardian", "guardian": gs[0].did, "keys": [w.newkey()]}, lambda b: list(b["keys"]) + [K(a)], tag="final")
    return a


@scenario("ACK-forged-guardian-log", "ACKNOWLEDGED (§12 Hostile registrar): evil.com serves a replacement log for bob; alice, not knowing bob's "
          "anchor, adds it; registrar accepts and resolvers report mutual", kinds=("verify", "registrar", "resolve"))
def _(w):
    w.root(); w.root("evil.com")
    a = w.create(D + ":alice")
    real = w.create("did:guardian:evil.com:bob")
    w.guard(real, w.create(D + ":someone"))                       # the real bob has history
    fake = Ident(real.did)
    k = w.newkey()
    w.push(fake, {"type": "create", "did": real.did, "keys": [k], "guardians": [], "successor": None, "policy": {}, "services": [],
                  "alsoKnownAs": [], "prev": None}, [k], attest=w.attestation(real.did))
    w.ids[real.did] = fake                                         # what evil.com now serves
    w.add_guardian(a, fake, tag="final")
    return a


@scenario("ATTACK-guard-superset", "FIXED at the registrar (S3-8): guardian unguards, then approves a recovery; verifies, standing rejects",
          kinds=("verify", "registrar", "resolve"), reg=False)
def _(w):
    a, gs = fixture(w, 1)
    g = gs[0]
    w.push(g, {"type": "releaseWard", "ward": a.did}, [K(g)])
    w.update(a, [GK(a, g.did)], tag="final")
    return a


@scenario("ATTACK-deactivated-root-attests", "FIXED (REQ-11-2): attestation from a deactivated root is rejected at resolution",
          kinds=("verify", "resolve"), res=False)
def _(w):
    r = w.root()
    w.push(r, {"type": "deactivate"}, [K(r)])
    return w.create(D + ":alice", tag="final")


@scenario("ATTACK-permuted-create", "FIXED (REQ-5-10): a permuted proof array no longer verifies", expect=False)
def _(w):
    w.root()
    a = w.create(D + ":alice", nkeys=2)
    a.log[0]["proof"].reverse()
    a.states = [apply(a.log[0], None)]
    return a


@scenario("guardian-and-successor-disjoint", "FIXED/defined (REQ-6-5): a guardian cannot also be the successor", expect=False)
def _(w):
    w.root(); a = w.create(D + ":alice"); b = w.create(D + ":bob", nkeys=2)
    w.guard(b, a)
    e = w.entry(b, a)
    w.push(a, {"type": "addGuardian", "entry": dict(e, keys=e["keys"][:1])}, lambda bd: bd["entry"]["keys"] + [K(a)])
    w.push(a, {"type": "setPolicy", "policy": {"orphan": "successor"}, "successor": dict(e, keys=e["keys"][1:])},
           lambda bd: [K(a), e["keys"][0]] + bd["successor"]["keys"], tag="final")
    return a


@scenario("mutual-guardians", "alice and bob guard each other (allowed)")
def _(w):
    w.root(); a = w.create(D + ":alice"); b = w.create(D + ":bob")
    w.add_guardian(a, b)
    w.add_guardian(b, a, tag="final")
    return b



@scenario("ATTACK-stale-evidence", "ATTACK (honest registrar, ONE ward key): guard0 once left (unguard) and later re-joined; a thief with alice's "
          "key cites the OLD unguard. FIXED at the registrar (R4-1): verifies, REQ-10-7 rejects", kinds=("verify", "registrar"), reg=False)
def _(w):
    a, gs = fixture(w, 2, {"orphan": "independent"})
    g0, g1 = gs
    w.push(a, {"type": "removeGuardian", "guardian": g0.did}, [GK(a, g0.did)])          # g0 leaves properly
    w.push(g0, {"type": "releaseWard", "ward": a.did}, [K(g0)])
    old_unguard = g0.head
    w.add_guardian(a, g0, approvers=[GK(a, g1.did)])                                     # later re-joins
    w.push(a, {"type": "removeGuardian", "guardian": g1.did}, [GK(a, g1.did)])          # g1 leaves; g0 is sole guardian
    w.push(a, {"type": "removeGuardian", "guardian": g0.did, "evidence": old_unguard}, [K(a)], tag="final")
    return a


@scenario("ATTACK-stale-evidence-deactivates", "ATTACK: same stale unguard under default orphan and deactivation.by=guardians: one ward key "
          "deactivates the identity. FIXED at the registrar (R4-1)", kinds=("verify", "registrar"), deact=True, reg=False)
def _(w):
    a, gs = fixture(w, 2, {"deactivation": {"by": "guardians", "threshold": "majority"}})
    g0, g1 = gs
    w.push(a, {"type": "removeGuardian", "guardian": g0.did}, [GK(a, g0.did)])
    w.push(g0, {"type": "releaseWard", "ward": a.did}, [K(g0)])
    old_unguard = g0.head
    w.add_guardian(a, g0, approvers=[GK(a, g1.did)])
    w.push(a, {"type": "removeGuardian", "guardian": g1.did}, [GK(a, g1.did)])
    w.push(a, {"type": "removeGuardian", "guardian": g0.did, "evidence": old_unguard}, [K(a)], tag="final")
    return a


@scenario("ATTACK-strip-redundant-proof", "ATTACK (no keys): a third party drops the superfluous guardian proof from a key-approved update; "
          "the result is a different valid operation with the same prev (a fork no key holder signed)")
def _(w):
    a, gs = fixture(w, 1)
    w.update(a, [K(a), GK(a, gs[0].did)], tag="final")
    a.log[-1]["proof"] = [p for p in a.log[-1]["proof"] if GK(a, gs[0].did) not in p["verificationMethod"]]
    return a


@scenario("STUCK-sole-guardian-left", "STUCK: the sole guardian unguards; alice cannot add a replacement (its approval lacks standing) -- "
          "verifies, registrar must reject; only evidence removal (deactivation under default orphan) remains", kinds=("verify", "registrar"), reg=False)
def _(w):
    a, gs = fixture(w, 1)
    w.push(gs[0], {"type": "releaseWard", "ward": a.did}, [K(gs[0])])
    h = w.create(D + ":helper")
    w.add_guardian(a, h, approvers=[GK(a, gs[0].did)], tag="final")
    return a


@scenario("evidence-unguard-removal", "removal citing the guardian's unguard (REQ-7-18); sole guardian -> orphan deactivate", kinds=("verify", "registrar"), deact=True)
def _(w):
    a, gs = fixture(w, 1)
    w.push(gs[0], {"type": "releaseWard", "ward": a.did}, [K(gs[0])])
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did, "evidence": gs[0].head}, [K(a)], tag="final")
    return a


@scenario("promote-via-evidence", "sole guardian unguarded; key + evidence removes it; the successor is promoted (REQ-10-7 row 5)",
          kinds=("verify", "registrar"), promoted=True)
def _(w):
    a, gs = fixture(w, 1, successor=True)
    w.push(gs[0], {"type": "releaseWard", "ward": a.did}, [K(gs[0])])
    w.push(a, {"type": "removeGuardian", "guardian": gs[0].did, "evidence": gs[0].head}, [K(a)], tag="final")
    return a


@scenario("rotate-reseat-approve", "guardian rotates, re-seats its entry, then approves a recovery: accepted", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 1)
    g = gs[0]
    old = K(g)
    w.update(g, [old])
    w.push(a, {"type": "updateGuardian", "guardian": g.did, "keys": list(g.state["keys"])}, lambda b: list(b["keys"]) + [old])
    w.update(a, [GK(a, g.did)], tag="final")
    return a


@scenario("wards-report", "REQ-11-6 rows from the guardian's side", kinds=("resolve",))
def _(w):
    w.root(); gina = w.create(D + ":gina")
    alice = w.create(D + ":alice"); w.add_guardian(alice, gina)
    carol = w.create(D + ":carol"); w.guard(gina, carol)
    w.push(carol, {"type": "setPolicy", "policy": {"orphan": "successor"}, "successor": w.entry(gina, carol)}, lambda b: [K(carol)] + b["successor"]["keys"])
    for n in ("dave", "erin", "frank"):
        w.guard(gina, w.create(D + ":" + n))
    w.push(gina, {"type": "update", "keys": gina.state["keys"], "services": [{"id": "#x", "type": "T", "serviceEndpoint": "https://x.example"}],
                  "alsoKnownAs": []}, [K(gina)], tag="final")
    return gina


@scenario("upd-successor", "successor rotates and refreshes its own entry with its old entry key (R4-3)", kinds=("verify", "registrar"))
def _(w):
    a, gs = fixture(w, 1, successor=True)
    sc = w.ids[D + ":succ"]
    old = K(sc)
    w.update(sc, [old])
    w.push(a, {"type": "updateGuardian", "guardian": sc.did, "keys": list(sc.state["keys"])}, lambda b: list(b["keys"]) + [old], tag="final")
    return a


@scenario("entry-keys-reordered", "entry lists the guardian's two keys in the other order; key lists compare as sets (REQ-5-5)",
          kinds=("verify", "registrar"))
def _(w):
    w.root(); a = w.create(D + ":alice"); g = w.create(D + ":gina", nkeys=2)
    w.guard(g, a)
    e = w.entry(g, a)
    e["keys"] = list(reversed(e["keys"]))
    w.push(a, {"type": "addGuardian", "entry": e}, lambda b: b["entry"]["keys"] + [K(a)], tag="final")
    return a


UNK = "https://example.org/ext/unknown"


def ext_op(w, a, ext=None, crit=None, keys=None, tag="final", signers=None):
    body = {"type": "update", "keys": keys if keys is not None else list(a.state["keys"]), "services": [], "alsoKnownAs": []}
    if ext is not None: body["extensions"] = ext
    if crit is not None: body["critical"] = crit
    return w.push(a, body, signers or (lambda b: [k for k in b["keys"] if k in w.privs] + [K(a)]), tag=tag)


@scenario("ext-noncritical-unknown", "non-critical unknown extension (object value) is ignored: valid")
def _(w):
    a, _ = fixture(w)
    ext_op(w, a, ext={UNK: {"anything": [1, 2]}})
    return a


@scenario("ext-critical-on-update", "critical on an update (only create/setPolicy may carry it, REQ-7-30); implemented name: invalid",
          result="invalid")
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=2)
    ext_op(w, a, ext={MINKEYS: {"k": 1}}, crit=[MINKEYS])
    return a


@scenario("ext-critical-unknown-on-update", "critical UNKNOWN name on an update: the unsupported test comes first (assumed): unsupported",
          result="unsupported")
def _(w):
    a, _ = fixture(w)
    ext_op(w, a, ext={UNK: 1}, crit=[UNK])
    return a


@scenario("ext-retro", "min-keys config carried non-critically earlier (ignored), made critical later: not retroactive (REQ-7-31)")
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=1)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None}, [K(a)])
    w.update(a, [K(a)], nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None, "critical": [MINKEYS]}, [K(a)], tag="final")
    return a


@scenario("ATTACK-fabricated-unsupported", "ATTACK (Y-1, no keys): append an operation with an unknown type, correct prev and a garbage "
          "proof; the whole log now reports unsupported, and no verifier can prove it was not a real future operation",
          result="unsupported")
def _(w):
    a, _ = fixture(w)
    w.update(a, [K(a)])
    a.log.append({"type": "rotateKeysV2", "prev": a.head, "proof": [dict(PC, cryptosuite="future-suite-2030",
                  verificationMethod=f"did:key:{K(a)}#{K(a)}", proofValue="z1111")]})
    a.states.append(a.state)
    return a


@scenario("unknown-type-first", "first operation has an unknown type: unsupported (assumed before REQ-7-3)", result="unsupported")
def _(w):
    a, _ = fixture(w)
    op = a.log[0]
    op["type"] = "createV2"
    return a


@scenario("attestation-unknown-suite", "attestation with an unknown cryptosuite: log verifies, resolution reports unsupported (REQ-11-2)",
          kinds=("verify", "resolve"), res="unsupported")
def _(w):
    w.root(); a = w.create(D + ":alice", tag="final")
    a.log[0]["attestation"]["cryptosuite"] = "ecdsa-sd-2023"
    return a


@scenario("ext-critical-unknown-policy", "critical unknown extension introduced in a policy: unsupported", result="unsupported")
def _(w):
    a, _ = fixture(w)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {UNK: 1}}, "successor": None, "critical": [UNK]}, [K(a)], tag="final")
    return a


@scenario("ext-critical-unknown-persists", "unknown critical on op 1, plain op 2: whole log unsupported", result="unsupported")
def _(w):
    a, _ = fixture(w)
    ext_op(w, a, ext={UNK: 1}, crit=[UNK], tag=None)
    w.update(a, [K(a)], tag="final")
    return a


@scenario("ext-minkeys-persist", "toy critical extension min-keys k=2 set by setPolicy; a later update keeps 2 keys: valid")
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None, "critical": [MINKEYS]}, [K(a)])
    w.update(a, [K(a)], nkeys=2, tag="final")
    return a


@scenario("ext-minkeys-N1", "N=1: setPolicy making min-keys critical needs key + guardian")
def _(w):
    a, gs = fixture(w, 1)
    w.update(a, [K(a)], nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None, "critical": [MINKEYS]},
           [K(a), GK(a, gs[0].did)], tag="final")
    return a


@scenario("ext-minkeys-introduce", "min-keys introduced with critical in a policy: valid")
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None, "critical": [MINKEYS]}, [K(a)], tag="final")
    return a


@scenario("ext-noncritical-ignored", "FIXED (X-1): min-keys configured but NOT critical; update to 1 key is valid for every conforming "
          "verifier (a non-conforming one that applies it would say invalid)", split=True)
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None}, [K(a)])
    w.update(a, [K(a)], nkeys=1, tag="final")
    return a


@scenario("ext-config-removal", "X-3 (REQ-7-35): min-keys defines removal of its configuration as invalid", result="invalid")
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None, "critical": [MINKEYS]}, [K(a)])
    w.push(a, {"type": "setPolicy", "policy": {}, "successor": None}, [K(a)], tag="final")
    return a


@scenario("ext-reassert", "FIXED (X-4): a later setPolicy re-lists min-keys in critical; union, valid")
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=2)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}}, "successor": None, "critical": [MINKEYS]}, [K(a)])
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 2}}, "maxWards": 4}, "successor": None, "critical": [MINKEYS]},
           [K(a)], tag="final")
    return a


@scenario("unsupported-after-invalid", "FIXED (X-2): op 1 has a corrupted signature, op 2 an unknown type: invalid (first stop)",
          result="invalid")
def _(w):
    a, _ = fixture(w)
    op = w.update(a, [K(a)])
    pv = bytearray(b58dec(op["proof"][0]["proofValue"][1:])); pv[7] ^= 1
    op["proof"][0]["proofValue"] = "z" + b58enc(bytes(pv))
    w.push(a, {"type": "rotate"}, [K(a)], tag="final")
    return a


@scenario("ACK-ext-critical-N0", "ACKNOWLEDGED (§12): with N=0 one key makes an extension critical via setPolicy; verifiers lacking it "
          "report unsupported from then on", kinds=("verify", "registrar"), poison=True)
def _(w):
    w.root(); a = w.create(D + ":alice", nkeys=1)
    w.push(a, {"type": "setPolicy", "policy": {"extensions": {MINKEYS: {"k": 1}}}, "successor": None, "critical": [MINKEYS]}, [K(a)], tag="final")
    return a


# ============================================================ mutations
def m_post(f): return {"post": f}
def m_body(f, tag="final"): return {"body": f, "tag": tag}
def m_specs(f, tag="final"): return {"specs": f, "tag": tag}
def m_before(f, tag="final"): return {"before": f, "tag": tag}
def m_vec(f): return {"vec": f}
def p0(op): return op["proof"][0]


def high_s(op, w, i):
    pv = b58dec(p0(op)["proofValue"][1:]); s = int.from_bytes(pv[32:], "big")
    p0(op)["proofValue"] = "z" + b58enc(pv[:32] + (P256_N - s).to_bytes(32, "big"))


def flip(op, w, i):
    pv = bytearray(b58dec(p0(op)["proofValue"][1:])); pv[7] ^= 1
    p0(op)["proofValue"] = "z" + b58enc(bytes(pv))


def flip_att(op, w, i):
    pv = bytearray(b58dec(op["attestation"]["proofValue"][1:])); pv[7] ^= 1
    op["attestation"]["proofValue"] = "z" + b58enc(bytes(pv))


def noncanon_sig(op, w, i):
    body = {k: v for k, v in op.items() if k not in ("proof", "attestation")}
    p = {k: v for k, v in p0(op).items() if k != "proofValue"}
    k = p["verificationMethod"].split("#")[1]
    data = hashlib.sha256(json.dumps(p, indent=1).encode()).digest() + hashlib.sha256(json.dumps(body, indent=1).encode()).digest()
    r, s = U.decode_dss_signature(w.privs[k].sign(data, ec.ECDSA(H.SHA256())))
    p0(op)["proofValue"] = "z" + b58enc(r.to_bytes(32, "big") + min(s, P256_N - s).to_bytes(32, "big"))


def key_variant(kind):
    def f(b, w, i):
        raw = b58dec(b["keys"][0][1:])
        b["keys"] = ["z" + b58enc({"raw": b"\x12\x00" + raw[2:], "k1": b"\xe7\x01" + raw[2:], "offcurve": MULTIKEY_P256 + b"\x02" + b"\xff" * 32}[kind])]
    return f


def setp(path, val):
    """body mutation: set nested member (path tuple) to val"""
    def f(b, w, i):
        o = b
        for p in path[:-1]: o = o[p]
        if val is DEL: o.pop(path[-1])
        else: o[path[-1]] = val(w, i, b) if callable(val) else copy.deepcopy(val)
    return f


DEL = object()
G0, G1, BOB = D + ":guard0", D + ":guard1", D + ":bob"
MUTS = []


def M(name, base, targets, desc, mut, kind="verify", result="invalid"):
    MUTS.append((name, base, targets, desc, dict(mut, result=result), kind))


def build():
    # ---- REQ-4
    for nm, did, req in (("4-1", "did:guardian:acme.com:al:ice", "REQ-4-1"), ("4-2-upper", "did:guardian:Acme.com:alice", "REQ-4-2"),
                         ("4-2-onelabel", "did:guardian:localhost:alice", "REQ-4-2"), ("4-2-numtld", "did:guardian:acme.123:alice", "REQ-4-2"),
                         ("4-2-ulabel", "did:guardian:bücher.de:alice", "REQ-4-2"), ("4-3-short", "did:guardian:acme.com:al", "REQ-4-3"),
                         ("4-3-hyphen", "did:guardian:acme.com:alice-", "REQ-4-3")):
        M(f"inv-{nm}", "create", req, f"DID changed to {did}", {"did": did, "tag": "final"})
    M("inv-8-1-did-mismatch", "create", "REQ-7-8", "vector DID differs from create.did", m_vec(lambda v, w: v.__setitem__("did", D + ":mallory")))
    # ---- REQ-5
    M("inv-5-1-nonchar", "create-full", "REQ-5-1", "service type contains U+FFFF", m_body(setp(("services", 0, "type"), "Hub￿")))
    M("inv-5-1-surrogate", "create-full", "REQ-5-1", "unpaired surrogate (after signing)", m_post(lambda op, w, i: op["services"][0].__setitem__("type", "\ud800")))
    M("inv-5-1-notobject", "update-key", "REQ-5-1", "last operation is a JSON string", m_vec(lambda v, w: v["log"].__setitem__(-1, "update")))
    for nm, val in (("float", 1.0), ("big", 2**53), ("neg", -1)):
        M(f"inv-5-2-{nm}", "setpolicy-N3", "REQ-5-2", f"policy.recovery = {val!r}", m_body(setp(("policy", "recovery"), val)))
    M("inv-5-3-top", "update-key", "REQ-5-3", "extra member", m_body(setp(("note",), "x")))
    M("inv-5-3-policy", "setpolicy-N0", "REQ-5-3", "unknown policy member", m_body(setp(("policy", "quorum"), 2)))
    M("inv-7-27-extra", "deactivate-N0", "REQ-7-27", "deactivate with extra member", m_body(setp(("reason",), "x")))
    M("inv-5-6-prev-sans-proof", "update-key", "REQ-5-6", "prev computed without proofs",
      m_body(lambda b, w, i: b.__setitem__("prev", hash_value({k: v for k, v in i.log[-1].items() if k != "proof"}))))
    M("inv-5-4-prev-noncanon", "update-key", "REQ-5-4", "prev over non-canonical JSON",
      m_body(lambda b, w, i: b.__setitem__("prev", "z" + b58enc(b"\x12\x20" + hashlib.sha256(json.dumps(i.log[-1]).encode()).digest()))))
    M("inv-5-4-sig-noncanon", "update-key", "REQ-5-4", "signature over non-canonical JSON", m_post(noncanon_sig))
    M("inv-5-6-attestation-edited", "update-key", "REQ-5-6", "op 0's attestation replaced after op 1 chained to it (hash covers attestation)",
      m_vec(lambda v, w: v["log"][0]["attestation"].__setitem__("verificationMethod", v["log"][0]["attestation"]["verificationMethod"].replace("#key-0", "#key-1"))))
    for kind, req in (("raw", "REQ-5-8"), ("k1", "REQ-5-8"), ("offcurve", "REQ-5-9")):
        M(f"inv-{req[4:]}-{kind}", "update-key", req, f"new key {kind}", m_body(key_variant(kind)))
    M("inv-5-10", "update-key", "REQ-5-10", "proof is an object", m_post(lambda op, w, i: op.__setitem__("proof", op["proof"][0])))
    M("inv-5-11-created", "update-key", "REQ-5-11", "proof has 'created'", m_post(lambda op, w, i: p0(op).__setitem__("created", "2026-01-01T00:00:00Z")))
    M("inv-5-11-purpose", "update-key", "REQ-5-11", "proofPurpose assertionMethod", m_post(lambda op, w, i: p0(op).__setitem__("proofPurpose", "assertionMethod")))
    M("inv-5-11-didref", "recovery-N1", "REQ-5-11", "guardian signs via a round-2 DID reference instead of a key reference",
      m_specs(lambda s, w, i: [s[0], (f"{G0}?versionId={w.ids[G0].head}#key-0", w.privs[s[1]])]))
    M("inv-5-11-keymismatch", "update-key", "REQ-5-11", "did:key fragment names another key",
      m_specs(lambda s, w, i: [s[0], (f"did:key:{s[1]}#{s[0]}", w.privs[s[1]])]))
    M("inv-5-12-suite-type", "update-key", "REQ-5-12", "cryptosuite is a number, not a name", m_post(lambda op, w, i: p0(op).__setitem__("cryptosuite", 7)))
    M("inv-5-12-encoding", "update-key", "REQ-5-12", "proofValue with 'u' prefix", m_post(lambda op, w, i: p0(op).__setitem__("proofValue", "u" + p0(op)["proofValue"][1:])))
    M("inv-5-12-attestation-in-doc", "create", "REQ-5-12", "proof signed over a document that includes the attestation",
      m_post(lambda op, w, i: op["proof"].__setitem__(0, w.proofs({k: v for k, v in op.items() if k != "proof"}, [op["keys"][0]])[0])))
    M("inv-5-13", "update-key", "REQ-5-13", "high-S", m_post(high_s))
    M("inv-5-14", "update-key", "REQ-5-14", "corrupted signature", m_post(flip))
    M("inv-5-14-tamper", "update-key", "REQ-5-14", "content changed after signing", m_post(lambda op, w, i: op.__setitem__("alsoKnownAs", ["https://x.example"])))
    M("inv-5-15", "update-key", "REQ-5-15", "same key signs twice", m_specs(lambda s, w, i: s + [s[-1]]))
    M("inv-7-5-not-in-entry", "guardian-two-keys", "REQ-7-5", "the guardian's approval is replaced by a key not in its entry",
      m_specs(lambda s, w, i: s[:1] + [w.newkey()]))
    # ---- REQ-6
    M("inv-6-1-nokeys", "update-key", "REQ-6-1", "zero keys", m_body(setp(("keys",), [])))
    M("inv-6-1-9keys", "update-key", "REQ-6-1", "9 keys", m_body(lambda b, w, i: b.__setitem__("keys", b["keys"] + [w.newkey() for _ in range(8)])))
    M("inv-6-1-dupkeys", "update-key", "REQ-6-1", "duplicate key", m_body(lambda b, w, i: b.__setitem__("keys", b["keys"] * 2)))
    M("inv-6-1-dupaka", "create-full", "REQ-6-1", "duplicate alsoKnownAs", m_body(lambda b, w, i: b.__setitem__("alsoKnownAs", b["alsoKnownAs"] * 2)))
    M("inv-6-1-aka-uri", "create-full", "REQ-6-1", "alsoKnownAs not a URI", m_body(setp(("alsoKnownAs",), ["not a uri"])))
    M("inv-6-1-33services", "create-full", "REQ-6-1", "33 services",
      m_body(setp(("services",), [{"id": f"#s{n}", "type": "T", "serviceEndpoint": "https://s.example"} for n in range(33)])))
    M("inv-6-1-dupsvc", "create-full", "REQ-6-1", "duplicate service id", m_body(lambda b, w, i: b.__setitem__("services", b["services"] * 2)))
    M("inv-6-2-didweb", "add-N0", "REQ-6-2", "entry did is did:web", m_body(setp(("entry", "did"), "did:web:gina.example")))
    M("inv-6-2-nokeys", "add-N0", "REQ-6-2", "entry with no keys", m_body(setp(("entry", "keys"), [])))
    M("inv-6-2-consent", "add-N0", "REQ-6-2", "entry consent is not a hash", m_body(setp(("entry", "consent"), "yes")))
    M("inv-6-2-extra", "add-N0", "REQ-6-2", "entry with extra member", m_body(setp(("entry", "note"), "x")))
    M("inv-6-3-entry-is-ward-key", "add-N0", "REQ-6-3", "entry keys = the ward's own key", m_body(lambda b, w, i: b["entry"].__setitem__("keys", [K(i)])))
    M("inv-6-3-update-guardian-key", "recovery-N1", "REQ-6-3", "recovery sets the ward's key to the guardian's entry key",
      m_body(lambda b, w, i: b.__setitem__("keys", [GK(i, G0)])))
    M("inv-6-3-successor-guardian-key", "setpolicy-successor", "REQ-6-3", "successor keys = the guardian's entry key",
      m_body(lambda b, w, i: b["successor"].__setitem__("keys", [GK(i, G0)])))
    M("inv-6-5-successor-is-guardian", "setpolicy-successor", "REQ-6-5", "successor entry names a current guardian's DID",
      m_body(lambda b, w, i: b["successor"].__setitem__("did", G0)))
    M("inv-5-10-unsorted", "create-two-keys", "REQ-5-10", "proof array not sorted", m_post(lambda op, w, i: op["proof"].reverse()))
    M("inv-6-2-anchor", "add-N0", "REQ-6-2", "entry anchor is not a hash", m_body(setp(("entry", "anchor"), "alice")))
    M("inv-6-4", "guard-key", "REQ-6-4", "ward record without anchor", m_body(lambda b, w, i: b["ward"].pop("anchor")))
    M("inv-6-5-guard-self", "guard-key", "REQ-6-5", "identity guards itself", m_body(setp(("ward",), lambda w, i, b: {"did": i.did, "anchor": i.anchor})))
    M("inv-6-5-add-self", "add-N0", "REQ-6-5", "identity adds itself as guardian",
      m_body(lambda b, w, i: b["entry"].__setitem__("did", i.did)))
    for nm, svc in (("nohash", {"id": "hub"}), ("badfrag", {"id": "#a b"}), ("extra", {"x": "y"}), ("objendpoint", {"serviceEndpoint": {"u": 1}}),
                    ("endpoint", {"serviceEndpoint": "no scheme"})):
        M(f"inv-6-6-{nm}", "create-full", "REQ-6-6", f"service {nm}", m_body(lambda b, w, i, svc=svc: b["services"][0].update(svc)))
    for n, cols in TABLE.items():
        for col, k in zip(("recovery", "membership", "removal", "deactivation"), cols):
            if k is not None:
                M(f"inv-table-N{n}-{col}", f"table-N{n}-{col}", "REQ-6-8", f"Appendix A N={n} {col}: one approval fewer", m_specs(lambda s, w, i: s[:-1]))
    for rec, n, k in (("all", 3, 3), (2, 5, 2), (1, 3, 2)):
        M(f"inv-recovery-{rec}-N{n}", f"recovery-{rec}-N{n}", "REQ-6-8", "one approval fewer", m_specs(lambda s, w, i: s[:-1]))
    M("inv-6-9-N2-removal", "remove-any-N2", "REQ-6-9", "same removal under the default policy (E=1, required 2)", m_body(setp(("policy",), {}), tag="alice"))
    M("inv-6-9-N1-remove-self", "remove-self-N2", "REQ-7-6", "last guardian tries to remove itself (N=1)",
      m_before(lambda w, i: w.push(i, {"type": "removeGuardian", "guardian": G1}, [GK(i, G1)])))
    for nm, p, req in (("recovery-bad", {"recovery": "some"}, "REQ-6-11"), ("membership-any", {"membership": "any"}, "REQ-6-11"),
                       ("orphan-bad", {"orphan": "abandon"}, "REQ-6-11"), ("maxwards-0", {"maxWards": 0}, "REQ-6-11"),
                       ("bool", {"recovery": True}, "REQ-6-11"), ("deact-missing", {"deactivation": {"by": "self"}}, "REQ-6-12"),
                       ("deact-by", {"deactivation": {"by": "nobody", "threshold": "all"}}, "REQ-6-12"),
                       ("k0", {"removal": 0}, "REQ-6-13"), ("k33", {"recovery": 33}, "REQ-6-13"),
                       ("threshold-40", {"deactivation": {"by": "self", "threshold": 40}}, "REQ-6-13"),
                       ("orphan-successor-null", {"orphan": "successor"}, "REQ-6-14")):
        M(f"inv-{req[4:]}-{nm}", "setpolicy-N0", req, f"policy {p}", m_body(setp(("policy",), p)))
    M("inv-6-14-successor-without-orphan", "setpolicy-successor", "REQ-6-14", "successor named but orphan left at default", m_body(setp(("policy",), {})))
    M("inv-6-15-guard", "maxwards", "REQ-6-15", "created with maxWards 1: the second guard exceeds it", m_body(setp(("policy",), {"maxWards": 1}), tag="alice"))
    M("inv-6-15-setpolicy", "maxwards-setpolicy", "REQ-6-15", "setPolicy lowers maxWards below the number of wards", m_body(setp(("policy",), {"maxWards": 1})))
    # ---- REQ-6-10 rows: deactivation followed by an operation
    M("inv-6-10-after-orphan-deactivate", "orphan-deactivate", "REQ-8-1", "an operation after the orphan deactivation",
      m_vec(lambda v, w: v["log"].append(_signed(w, w.ids[v["did"]], {"type": "update", "keys": w.ids[v["did"]].states[-2]["keys"], "services": [],
                                                                          "alsoKnownAs": [], "prev": op_hash(v["log"][-1])}, w.ids[v["did"]].states[-2]["keys"]))))
    # ---- REQ-7
    M("inv-7-1-create", "create", "REQ-7-1", "create without prev", m_post(lambda op, w, i: op.pop("prev")))
    M("inv-7-1-deactivate", "deactivate-N0", "REQ-7-1", "deactivate without proof", m_post(lambda op, w, i: op.pop("proof")))
    M("inv-7-2", "update-key", "REQ-7-2", "type is a number (an unknown string type is unsupported, not invalid)", m_body(setp(("type",), 5)))
    M("inv-7-3-later-create", "update-key", "REQ-7-3", "second operation typed create", m_body(setp(("type",), "create")))
    M("inv-7-3-first-not-create", "create", "REQ-7-3", "first operation typed update", m_body(setp(("type",), "update")))
    M("inv-7-4-prev", "update-key", "REQ-7-4", "prev wrong", m_body(lambda b, w, i: b.__setitem__("prev", op_hash(i.log[0])[:-2] + "zz")))
    M("inv-7-4-createprev", "create", "REQ-7-4", "create prev not null", m_body(setp(("prev",), "zQmX")))
    M("inv-7-5-stranger", "update-key", "REQ-7-5", "extra proof from an unrelated key", m_specs(lambda s, w, i: s + [w.newkey()]))
    M("inv-7-5-removed-ward-key", "update-key", "REQ-7-5", "alice's key is rotated just before; the final op is still signed by the removed key",
      m_before(lambda w, i: w.update(i, [K(i)])))
    # REQ-7-6 every row: one missing approval each
    rows = [("create-key", "create-two-keys", lambda s, w, i: s[:1]), ("create-guardian", "appendix-create", lambda s, w, i: s[:1]),
            ("update-newkey", "update-key", lambda s, w, i: s[1:]), ("update-takeover", "update-key", lambda s, w, i: s[:1]),
            ("add-entrykey", "add-N0", lambda s, w, i: s[1:]), ("add-currentkey", "add-N1", lambda s, w, i: [s[0], s[2]]),
            ("add-membership", "add-N1", lambda s, w, i: s[:2]), ("updg-newkeys", "upd-guardian-self", lambda s, w, i: s[1:]),
            ("updg-entrykey", "upd-guardian-self", lambda s, w, i: s[:1]), ("updg-lost-other", "upd-guardian-lost", lambda s, w, i: s[:2]),
            ("updg-lost-key", "upd-guardian-lost", lambda s, w, i: [s[0], s[2]]),
            ("remove-key-only", "remove-self-N2", lambda s, w, i: [i.state["keys"][0]]),
            ("remove-evidence-none", "remove-evidence-key", lambda s, w, i: []),
            ("remove-successor-nokey", "orphan-successor", lambda s, w, i: [i.state["successor"]["keys"][0]]),
            ("remove-successor-nosucc", "orphan-successor", lambda s, w, i: [K(i)]),
            ("setpolicy-nokey", "setpolicy-N3", lambda s, w, i: s[1:]), ("setpolicy-membership", "setpolicy-N3", lambda s, w, i: s[:2]),
            ("setpolicy-successor-keys", "setpolicy-successor", lambda s, w, i: s[:2]),
            ("guard-none", "guard-key", lambda s, w, i: []), ("unguard-none", "unguard-key", lambda s, w, i: []),
            ("deact-N0", "deactivate-N0", lambda s, w, i: []), ("deact-self", "deact-self-k", lambda s, w, i: []),
            ("deact-guardians", "deact-guardians-g", lambda s, w, i: s[:1]), ("deact-guardians-keyonly", "deact-guardians-g", lambda s, w, i: [i.state["keys"][0]]),
            ("deact-either", "deact-either-k", lambda s, w, i: []), ("deact-both-nokey", "deact-both-kg", lambda s, w, i: s[1:]),
            ("deact-both-noguardians", "deact-both-kg", lambda s, w, i: s[:1])]
    for nm, base, f in rows:
        M(f"inv-7-6-{nm}", base, "REQ-7-6", f"REQ-7-6 row: {nm} approval missing", m_specs(f))
    M("inv-7-7-successor", "create", "REQ-7-7", "create without successor member", m_body(lambda b, w, i: b.pop("successor")))
    M("inv-7-7-attestation", "create", "REQ-7-7", "non-root create without attestation", m_post(lambda op, w, i: op.pop("attestation")))
    M("inv-5-3-root-attestation", "root", "REQ-5-3", "root create carrying an attestation (assumed not allowed)",
      m_post(lambda op, w, i: op.__setitem__("attestation", dict(op["proof"][0], verificationMethod=f"{D}?versionId=zQmX#key-0"))))
    M("inv-7-9-domain", "create", "REQ-7-9", "attestation names another domain's root",
      m_post(lambda op, w, i: op["attestation"].__setitem__("verificationMethod", op["attestation"]["verificationMethod"].replace("acme.com", "other.com"))))
    M("inv-7-9-keyref", "create", "REQ-7-9", "attestation is a did:key reference",
      m_post(lambda op, w, i: op["attestation"].__setitem__("verificationMethod", f"did:key:{op['keys'][0]}#{op['keys'][0]}")))
    M("inv-7-10", "update-key", "REQ-7-10", "update without services", m_body(lambda b, w, i: b.pop("services")))
    M("inv-7-12", "add-N0", "REQ-7-12", "addGuardian without entry", m_body(lambda b, w, i: b.pop("entry")))
    M("inv-7-13", "add-N1", "REQ-7-13", "add an existing guardian", m_body(lambda b, w, i: b["entry"].__setitem__("did", G0)))
    M("inv-7-15", "upd-guardian-self", "REQ-7-15", "updateGuardian of a non-guardian", m_body(setp(("guardian",), D + ":nobody")))
    M("inv-7-15-members", "upd-guardian-self", "REQ-7-15", "updateGuardian without keys", m_body(lambda b, w, i: b.pop("keys")))
    M("inv-7-17", "remove-self-N2", "REQ-7-17", "removeGuardian of a non-guardian", m_body(setp(("guardian",), D + ":nobody")))
    M("inv-7-18", "remove-evidence-key", "REQ-7-18", "evidence is not an operation hash", m_body(setp(("evidence",), "deactivated!")))
    M("inv-7-20", "setpolicy-N0", "REQ-7-20", "setPolicy without successor member", m_body(lambda b, w, i: b.pop("successor")))
    M("inv-7-22", "guard-key", "REQ-7-22", "guard without ward", m_body(lambda b, w, i: b.pop("ward")))
    M("inv-7-23", "guard-key", "REQ-7-23", "guard the same ward twice", m_before(lambda w, i: w.guard(i, w.ids[D + ":carol"])))
    M("inv-7-25", "unguard-key", "REQ-7-25", "unguard a DID not in wards", m_body(setp(("ward",), D + ":nobody")))
    M("inv-7-28", "deactivate-N0", "REQ-8-1", "an update after deactivate",
      m_vec(lambda v, w: v["log"].append(_signed(w, w.ids[v["did"]], {"type": "update", "keys": w.ids[v["did"]].states[-2]["keys"], "services": [],
                                                                          "alsoKnownAs": [], "prev": op_hash(v["log"][-1])}, w.ids[v["did"]].states[-2]["keys"]))))
    M("inv-8-1-empty", "create", "REQ-8-1", "empty log", m_vec(lambda v, w: v.__setitem__("log", [])))
    M("ext-inv-critical-without-membership", "ext-minkeys-N1", "REQ-7-6", "X-5: with a guardian, the ward key alone cannot make an extension critical",
      m_specs(lambda s, w, i: s[:1]))
    M("ext-inv-minkeys-later", "ext-minkeys-persist", "REQ-7-33", "critical min-keys persists: a later update to 1 key is invalid",
      m_body(lambda b, w, i: b.__setitem__("keys", b["keys"][:1])))
    M("ext-inv-minkeys-introduce-violates", "ext-minkeys-introduce", "REQ-7-33", "min-keys k=3 introduced while only 2 keys",
      m_body(lambda b, w, i: b["policy"]["extensions"].__setitem__(MINKEYS, {"k": 3})))
    M("ext-inv-minkeys-config", "ext-minkeys-introduce", "REQ-7-33", "bad min-keys configuration", m_body(lambda b, w, i: b["policy"]["extensions"].__setitem__(MINKEYS, {"k": "two"})))
    M("ext-inv-critical-absent", "ext-minkeys-introduce", "REQ-7-30", "critical names min-keys but no extensions member carries it",
      m_body(lambda b, w, i: b["policy"].pop("extensions")))
    M("ext-uns-critical-absent-unknown", "ext-minkeys-introduce", "REQ-8-1", "setPolicy critical names an unknown, absent extension: unsupported",
      m_body(lambda b, w, i: b.__setitem__("critical", ["https://example.org/ext/other"])), result="unsupported")
    M("ext-inv-critical-empty", "ext-minkeys-introduce", "REQ-7-30", "critical is an empty list", m_body(lambda b, w, i: b.__setitem__("critical", [])))
    M("ext-inv-critical-op-level", "ext-minkeys-introduce", "REQ-7-30", "min-keys moved from policy.extensions to the operation's own extensions",
      m_body(lambda b, w, i: b.__setitem__("extensions", b["policy"].pop("extensions"))))
    M("ext-inv-critical-dup", "ext-minkeys-introduce", "REQ-7-30", "critical lists a name twice", m_body(lambda b, w, i: b.__setitem__("critical", [MINKEYS, MINKEYS])))
    M("ext-inv-name-not-uri", "ext-noncritical-unknown", "REQ-7-29", "extension name is not a URI", m_body(lambda b, w, i: b.__setitem__("extensions", {"minkeys": 1})))
    M("ext-inv-name-fragment", "ext-noncritical-unknown", "REQ-7-29", "extension name has a fragment (not absolute)",
      m_body(lambda b, w, i: b.__setitem__("extensions", {UNK + "#x": 1})))
    M("ext-inv-not-object", "ext-noncritical-unknown", "REQ-7-29", "extensions is a list", m_body(lambda b, w, i: b.__setitem__("extensions", [UNK])))
    M("ext-inv-policy-member", "setpolicy-N0", "REQ-5-3", "policy carries 'critical' (only 'extensions' is allowed in a policy)",
      m_body(lambda b, w, i: b["policy"].__setitem__("critical", [UNK])))
    M("ext-inv-tamper-ignored", "ext-noncritical-unknown", "REQ-7-34", "an ignored extension is edited after signing: still invalid (secured document)",
      m_post(lambda op, w, i: op["extensions"].__setitem__(UNK, {"anything": [3]})))
    M("ext-uns-type", "update-key", "REQ-8-1", "unknown type 'rotateKeys'", m_body(setp(("type",), "rotateKeys")), result="unsupported")
    M("ext-uns-cryptosuite", "update-key", "REQ-8-1", "unknown cryptosuite", m_post(lambda op, w, i: p0(op).__setitem__("cryptosuite", "ecdsa-rdfc-2019")), result="unsupported")
    M("ext-uns-on-create", "create", "REQ-8-1", "create with a critical unknown extension", m_body(lambda b, w, i: b.update(extensions={UNK: 1}, critical=[UNK])), result="unsupported")

    # ---- registrar (REQ-10-5 .. 10-8)
    R = lambda name, base, targets, desc, mut: M(name, base, targets, desc, mut, "registrar")
    R("reg-inv-10-5-prev", "add-N1", "REQ-10-5", "prev is not the version of the log", m_body(setp(("prev",), "zQmStale")))
    R("reg-inv-10-6-stale-entry", "add-N1", "REQ-10-6", "guardian rotated after its guard: entry keys are stale",
      m_before(lambda w, i: w.update(w.ids[D + ":gina"], [K(w.ids[D + ":gina"])])) | {"body": lambda b, w, i: None})
    R("reg-inv-10-6-deactivated", "add-N0", "REQ-10-6", "guardian deactivated after its guard",
      m_before(lambda w, i: w.push(w.ids[D + ":gina"], {"type": "deactivate"}, [K(w.ids[D + ":gina"])])))
    R("reg-inv-10-6-consent-not-guard", "add-N0", "REQ-10-6", "consent names the guardian's create, not its guard",
      m_body(lambda b, w, i: b["entry"].__setitem__("consent", op_hash(w.ids[D + ":gina"].log[0]))))
    R("reg-inv-10-6-unguarded", "add-N0", "REQ-10-6", "guardian unguarded before the add",
      m_before(lambda w, i: w.push(w.ids[D + ":gina"], {"type": "releaseWard", "ward": i.did}, [K(w.ids[D + ":gina"])])))
    R("reg-inv-10-6-updg-not-current", "upd-guardian-self", "REQ-10-6", "updateGuardian keys are not the guardian's current keys",
      {"tag": "final", "body": lambda b, w, i: b.__setitem__("keys", [w.newkey()])})
    R("reg-inv-10-6-evidence", "remove-evidence-key", "REQ-10-6", "evidence is the guardian's create, not a deactivate",
      m_body(lambda b, w, i: b.__setitem__("evidence", op_hash(w.ids[G0].log[0]))))
    R("reg-inv-10-6-guard-anchor", "guard-key", "REQ-10-6", "guard names a wrong anchor for an existing ward",
      m_body(lambda b, w, i: b["ward"].__setitem__("anchor", op_hash(w.ids[D + ":carol"].log[0]))))
    R("reg-inv-10-6-successor-stale", "setpolicy-successor", "REQ-10-6", "successor rotated after its guard: setPolicy entry keys stale",
      m_before(lambda w, i: w.update(w.ids[D + ":succ"], [K(w.ids[D + ":succ"])])))
    R("reg-inv-10-8-root-version", "create", "REQ-10-8", "root rotated before the create; attestation names the old version",
      {"tag": "final", "before": lambda w, i: w.update(w.ids[D], [K(w.ids[D])]), "post": lambda op, w, i: op.__setitem__("attestation", _att_at(w, op, 0))})
    R("reg-inv-row1-anchor", "add-N0", "REQ-10-7", "row 1: entry anchor is not gina's anchor",
      m_body(lambda b, w, i: b["entry"].__setitem__("anchor", op_hash(w.ids[D + ":gina"].log[0]))))
    R("reg-inv-row1-appendix-stale", "appendix-create", "REQ-10-7", "row 1: Bob rotates after his guard, before Alice's create",
      m_before(lambda w, i: w.update(w.ids[BOB], [K(w.ids[BOB])])))
    for nm, f in (("rotated", lambda w, i: w.update(w.ids[G0], [K(w.ids[G0])])),
                  ("unguarded", lambda w, i: w.push(w.ids[G0], {"type": "releaseWard", "ward": i.did}, [K(w.ids[G0])])),
                  ("deactivated", lambda w, i: w.push(w.ids[G0], {"type": "deactivate"}, [K(w.ids[G0])]))):
        R(f"reg-inv-row2-{nm}", "recovery-N1", "REQ-10-7", f"row 2: approving guardian {nm} before the recovery (no standing)", m_before(f))
    R("reg-inv-row4-has-standing", "evidence-unguard-removal", "REQ-10-7", "row 4: guard0 re-guarded after its unguard; entry has standing again",
      m_before(lambda w, i: w.guard(w.ids[G0], i)))
    R("reg-inv-row4-before-consent", "remove-evidence-key", "REQ-10-7", "row 4: evidence predates the consent",
      m_body(lambda b, w, i: b.__setitem__("evidence", op_hash(w.ids[G0].log[0]))))
    R("reg-inv-ext-unsupported", "ACK-ext-critical-N0", "REQ-10-5", "registrar that does not implement min-keys must reject", {"tag": "final", "unsup": True})
    R("reg-inv-row4-unguard-other", "evidence-unguard-removal", "REQ-10-7", "row 4: evidence is guard0's unguard of another ward",
      {"tag": "final", "before": _unguard_zed, "body": lambda b, w, i: b.__setitem__("evidence", w.ids[G0].head)})
    R("reg-inv-row5-promote-stale", "promote-via-evidence", "REQ-10-7", "row 5: successor rotated before an evidence removal promotes it",
      m_before(lambda w, i: w.update(w.ids[D + ":succ"], [K(w.ids[D + ":succ"])])))
    R("reg-inv-row5-successor-stale", "orphan-successor", "REQ-10-7", "row 5: successor rotated before promotion",
      m_before(lambda w, i: w.update(w.ids[D + ":succ"], [K(w.ids[D + ":succ"])])))

    # ---- resolve (§11)
    S = lambda name, base, targets, desc, mut: M(name, base, targets, desc, mut, "resolve")
    S("res-inv-11-2-sig", "create", "REQ-11-2", "attestation signature corrupted (log still verifies alone)", m_post(flip_att))
    S("res-inv-11-2-version", "create", "REQ-11-2", "attestation names a version not in the root log",
      m_post(lambda op, w, i: op.__setitem__("attestation", _att_vm(w, op, f"{D}?versionId=zQmVz9vELvxPX7XxbP3EALZyiGeBNqzpLZkLsHk9V4cZrg8#key-0"))))
    S("res-inv-11-2-index", "create", "REQ-11-2", "attestation names key-1 the root does not have",
      m_post(lambda op, w, i: op.__setitem__("attestation", _att_vm(w, op, op["attestation"]["verificationMethod"].replace("#key-0", "#key-1")))))
    S("res-inv-11-2-rootlog", "create", "REQ-11-2", "root log unavailable", m_vec(lambda v, w: v["resolver"].pop(D)))
    S("res-11-5-keys-out-of-date", "add-N1", "REQ-11-5", "gina rotates after being added: keys out of date",
      m_vec(lambda v, w: _then(v, w, lambda: w.update(w.ids[D + ":gina"], [K(w.ids[D + ":gina"])]))))
    S("res-11-5-withdrawn", "add-N1", "REQ-11-5", "gina unguards after being added: withdrawn",
      m_vec(lambda v, w: _then(v, w, lambda: w.push(w.ids[D + ":gina"], {"type": "releaseWard", "ward": v["did"]}, [K(w.ids[D + ":gina"])]))))
    S("res-11-5-deactivated", "add-N1", "REQ-11-5", "gina deactivates after being added: withdrawn",
      m_vec(lambda v, w: _then(v, w, lambda: w.push(w.ids[D + ":gina"], {"type": "deactivate"}, [K(w.ids[D + ":gina"])]))))
    S("res-11-5-unavailable", "add-N1", "REQ-11-5", "gina's log unavailable", m_vec(lambda v, w: v["resolver"].pop(D + ":gina")))
    S("res-11-5-different", "add-N1", "REQ-11-5", "gina's registrar serves a different identity", m_vec(lambda v, w: _swap_identity(v, w, D + ":gina")))
    S("res-11-6-rows", "wards-report", "REQ-11-6", "erin's log unavailable, frank replaced",
      m_vec(lambda v, w: (v["resolver"].pop(D + ":erin"), _swap_identity(v, w, D + ":frank"))))


def _signed(w, idn, body, keys):
    return dict(body, proof=w.proofs(secured(body), keys))


def _att_vm(w, op, vm):
    root = w.ids[D]
    p = dict(PC, verificationMethod=vm)
    p["proofValue"] = sign_jcs(w.privs[root.states[0]["keys"][0]], secured(op), p)
    return p


def _att_at(w, op, vi):
    root = w.ids[D]
    return _att_vm(w, op, f"{D}?versionId={op_hash(root.log[vi])}#key-0")


def _then(v, w, f):
    f()
    v["resolver"] = {d: copy.deepcopy(i.log) for d, i in w.ids.items() if d != v["did"]}


def _unguard_zed(w, i):
    g = w.ids[G0]
    z = w.create(D + ":zed")
    w.guard(g, z)
    w.push(g, {"type": "releaseWard", "ward": z.did}, [K(g)])


def _swap_identity(v, w, did):
    x = Ident(did)
    k = w.newkey()
    w.push(x, {"type": "create", "did": did, "keys": [k], "guardians": [], "successor": None, "policy": {"maxWards": 9}, "services": [],
               "alsoKnownAs": [], "prev": None}, [k], attest=w.attestation(did))
    v["resolver"][did] = x.log


def _reg_from(v, w, scen):
    vv, ww, tt, _ = run_scenario(scen)
    v.update(log=[], op=vv["log"][-1], resolver=ww.snap)


# ============================================================ emit
def run_scenario(name, mut=None):
    f, desc, kinds, extra = SC[name]
    w = World(mut)
    t = f(w)
    v = {"description": desc, "did": t.did, "log": copy.deepcopy(t.log),
         "resolver": {d: copy.deepcopy(i.log) for d, i in w.ids.items() if d != t.did}, "expect": {"valid": True}}
    if w.snap is None:
        w.snap = v["resolver"]
    return v, w, t, extra


def as_kind(v, w, kind, valid):
    if kind == "registrar":
        return dict(v, kind="registrar", log=v["log"][:-1], op=v["log"][-1], resolver=w.snap, expect={"accepted": valid})
    if kind == "resolve":
        return dict(v, kind="resolve", expect={"valid": valid})
    return v


EXPECT_REG = {"ATTACK-fake-evidence": False}
EXPECT_RES = {"appendix-create": ("mutual",), "ATTACK-guard-superset": ("withdrawn",), "ACK-forged-guardian-log": ("mutual",), "wards-report": (),
              "add-N1": ("mutual", "mutual")}


def main():
    VT = {"root": "REQ-4-4", "create": "REQ-5-7", "create-full": "REQ-9-2", "appendix-create": "REQ-7-6", "guardian-two-keys": "REQ-5-16",
          "update-key": "REQ-7-11", "add-N0": "REQ-7-14", "upd-guardian-self": "REQ-7-16", "upd-guardian-lost": "REQ-7-6",
          "upd-guardian-sole": "REQ-7-6", "remove-self-N2": "REQ-7-19", "orphan-deactivate": "REQ-6-10", "orphan-independent": "REQ-6-10",
          "orphan-successor": "REQ-6-10", "setpolicy-N0": "REQ-7-21", "guard-key": "REQ-7-24", "unguard-key": "REQ-7-26",
          "deactivate-N0": "REQ-9-3", "maxwards": "REQ-6-15", "mutual-guardians": "REQ-6-5",
          "ext-reassert": "REQ-7-32", "ext-noncritical-ignored": "REQ-7-34", "ext-retro": "REQ-7-31", "ext-config-removal": "REQ-7-35",
          "deact-self-k": "REQ-7-28", "entry-keys-reordered": "REQ-5-5", "create-two-keys": "REQ-9-4"}
    build()
    vecs = []
    for name, (f, desc, kinds, extra) in SC.items():
        v, w, t, _ = run_scenario(name)
        v["targets"] = VT.get(name) or ("REQ-6-8" if name.startswith(("table", "recovery-")) else "REQ-7-6" if name.startswith("deact-") else None)
        v["anchor"] = anchor_of(t.log)
        if extra.get("doc"):
            st = t.states[-1]
            ids = [f"{t.did}#key-{n}" for n in range(len(st["keys"]))]
            v["expectDocument"] = ({"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": t.did}
                                   if st["deactivated"] else
                                   {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": t.did,
                                    "verificationMethod": [{"id": i, "type": "Multikey", "controller": t.did, "publicKeyMultibase": k} for i, k in zip(ids, st["keys"])],
                                    "authentication": ids, "assertionMethod": ids, "capabilityInvocation": ids,
                                    "service": [{"id": t.did + "#hub", "type": "Hub", "serviceEndpoint": "https://hub.example/a"}],
                                    "alsoKnownAs": ["https://alice.example"]})
        if extra.get("deact"): v["expectState"] = {"deactivated": True}
        if extra.get("promoted"): v["expectState"] = {"guardians": [w.ids[t.did].states[-2]["successor"]["did"]], "successor": None, "orphan": "deactivate"}
        for kind in kinds:
            if kind == "verify":
                r = extra.get("result") or {True: "valid", False: "invalid"}[extra.get("expect", True)]
                vv = dict(v, expect={"result": r})
                if extra.get("split"): vv["splitIfEnforced"] = True
                if extra.get("poison"): vv["unsupportedWithout"] = [MINKEYS]
                vecs.append((name, vv))
            elif kind == "registrar":
                vecs.append(("reg-" + name, as_kind(v, w, kind, extra.get("reg", EXPECT_REG.get(name, True))) | {"base": None}))
            else:
                rres = extra.get("res", True)
                rv = as_kind(v, w, kind, rres is True)
                if isinstance(rres, str): rv["expectResult"] = rres
                if name == "wards-report":
                    rv["expectWardReports"] = [["alice", "guardian"], ["carol", "successor"], ["dave", "not related"], ["erin", "not related"], ["frank", "not related"]]
                if name in EXPECT_RES: rv["expectMutuality"] = list(EXPECT_RES[name])
                vecs.append(("res-" + name, rv))
    for name, base, targets, desc, mut, kind in MUTS:
        hooks = {k: x for k, x in mut.items() if k not in ("vec", "result", "unsup") and x is not None}
        v, w, t, _ = run_scenario(base, hooks)
        if kind != "verify":
            v = as_kind(v, w, kind, False)
        if mut.get("vec"): mut["vec"](v, w)
        v.update(description=desc, targets=targets, base=("reg-" if kind == "registrar" else "res-" if kind == "resolve" else "") + base)
        if kind == "verify": v["expect"] = {"result": mut["result"]}
        if mut.get("unsup"): v["implemented"] = []
        if name in ("res-11-5-keys-out-of-date", "res-11-5-withdrawn", "res-11-5-deactivated", "res-11-5-unavailable", "res-11-5-different", "res-11-6-rows"):
            v["expect"] = {"valid": True}
            v["expectMutuality"] = {"res-11-5-keys-out-of-date": ["mutual", "keys out of date"], "res-11-5-withdrawn": ["mutual", "withdrawn"],
                                    "res-11-5-deactivated": ["mutual", "deactivated"], "res-11-5-unavailable": ["mutual", "unavailable"],
                                    "res-11-5-different": ["mutual", "different identity"], "res-11-6-rows": []}[name]
            if name == "res-11-6-rows":
                v["expectWardReports"] = [["alice", "guardian"], ["carol", "successor"], ["dave", "not related"], ["erin", "unavailable"], ["frank", "different identity"]]
        vecs.append((name, v))
    import re as _re
    ren = lambda x: _re.sub(r"(?<![a-zA-Z])guard(?=[-\s.,;:)]|$)", "accept-ward", _re.sub(r"(?<![a-zA-Z])unguard(?:ed|s)?", "release-ward", x))
    vecs = [(ren(n), dict(v, description=ren(v["description"]), **({"base": ren(v["base"])} if v.get("base") else {}))) for n, v in vecs]
    for _, v in vecs:                                 # uniform expect.result
        if v.get("kind") == "registrar":
            v["expect"] = {"result": "accepted" if v["expect"]["accepted"] else "rejected"}
        elif v.get("kind") == "resolve":
            v["expect"] = {"result": v.pop("expectResult", None) or ("valid" if v["expect"]["valid"] else "invalid")}
        if v.get("base") is None: v.pop("base", None)
    shutil.rmtree(OUT, ignore_errors=True); os.makedirs(OUT)
    for name, v in vecs:
        with open(os.path.join(OUT, name + ".json"), "w") as f:
            json.dump(v, f, indent=1)
    print(f"wrote {len(vecs)} vectors to {OUT}")


if __name__ == "__main__":
    main()
