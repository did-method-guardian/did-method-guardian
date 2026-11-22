"""Clean-room did:guardian verifier, final spec revision (sections 5-11)."""
import copy, hashlib, re
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MULTIKEY_P256 = b"\x80\x24"                     # REQ-5-8
MAX_INT = 2**53 - 1
CTX = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]


class Invalid(Exception):
    def __init__(self, req, msg):
        super().__init__(f"{req}: {msg}")
        self.req, self.msg = req, msg


# ---------------------------------------------------------------- encodings
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58enc(b):
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def b58dec(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            raise ValueError("bad base58 char")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_str(s):
    return '"' + "".join(_ESC.get(c) or ("\\u%04x" % ord(c) if ord(c) < 0x20 else c) for c in s) + '"'


def _jcs_num(x):
    if isinstance(x, int):
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    if "e" in r:
        m, e = r.split("e")
        r = m.rstrip("0").rstrip(".") + "e" + ("+" if int(e) > 0 else "-") + str(abs(int(e)))
    return r


def jcs(v):
    """RFC 8785 canonical serialization."""
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, (int, float)): return _jcs_num(v)
    if isinstance(v, str): return _jcs_str(v)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_jcs_str(k) + ":" + jcs(v[k]) for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise ValueError("not JSON")


def jcs_bytes(v):
    return jcs(v).encode("utf-8")


def hash_value(v):
    """REQ-5-5."""
    try:
        data = jcs_bytes(v)
    except UnicodeEncodeError:
        raise Invalid("REQ-5-1", "string contains an unpaired surrogate")
    except ValueError as e:
        raise Invalid("REQ-5-1", str(e))
    return "z" + b58enc(b"\x12\x20" + hashlib.sha256(data).digest())


def op_hash(op):
    """REQ-5-6: hash of the complete operation, proofs included."""
    return hash_value(op)


def anchor_of(log):
    """REQ-5-7: first operation without proof, attestation, guardians and successor."""
    return hash_value({k: v for k, v in log[0].items() if k not in ("proof", "attestation", "guardians", "successor")})


def keys_eq(a, b):
    """REQ-5-5: key lists are equal as sets."""
    return set(a) == set(b)


def decode_key(k):
    """REQ-5-8, REQ-5-9."""
    try:
        assert isinstance(k, str) and k.startswith("z")
        raw = b58dec(k[1:])
        assert len(raw) == 35 and raw[:2] == MULTIKEY_P256 and raw[2] in (2, 3) and "z" + b58enc(raw) == k
    except Exception:
        raise Invalid("REQ-5-8", f"not a P-256 Multikey: {str(k)[:60]}")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw[2:])
    except Exception:
        raise Invalid("REQ-5-9", f"point not on P-256: {k[:60]}")


def encode_key(pub):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return "z" + b58enc(MULTIKEY_P256 + pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))


# ------------------------------------------------------- ecdsa-jcs-2019 (REQ-5-12)
def hash_data(document, proof):
    cfg = {k: v for k, v in proof.items() if k != "proofValue"}
    if "@context" in document:                    # cryptosuite rule; never true for operations
        cfg["@context"] = document["@context"]
    return hashlib.sha256(jcs_bytes(cfg)).digest() + hashlib.sha256(jcs_bytes(document)).digest()


def sign_jcs(priv, document, proof):
    r, s = utils.decode_dss_signature(priv.sign(hash_data(document, proof), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    s = min(s, P256_N - s)                        # REQ-5-13
    return "z" + b58enc(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_jcs(pub, document, proof, req="REQ-5-14"):
    pv = proof.get("proofValue")
    try:
        assert isinstance(pv, str) and pv.startswith("z")
        raw = b58dec(pv[1:])
        assert len(raw) == 64
    except Exception:
        raise Invalid("REQ-5-12", "proofValue is not a base58btc 64-byte signature")
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if not (0 < r < P256_N and 0 < s < P256_N):
        raise Invalid(req, "signature scalar out of range")
    if s > P256_N // 2:
        raise Invalid("REQ-5-13", "high-S signature")
    try:
        pub.verify(utils.encode_dss_signature(r, s), hash_data(document, proof), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Invalid(req, "signature does not verify")


# ------------------------------------------------------------- identifiers
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{1,30}[a-z0-9]")
_U = r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})"
URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
FRAGMENT = re.compile("#" + _U + "*")


def parse_did(d):
    """REQ-4-1..4-3. Returns (domain, name|None)."""
    if not isinstance(d, str) or not d.startswith("did:guardian:"):
        raise Invalid("REQ-4-1", f"not a did:guardian DID: {d!r}")
    parts = d[len("did:guardian:"):].split(":")
    if len(parts) not in (1, 2):
        raise Invalid("REQ-4-1", f"wrong number of segments: {d!r}")
    dom, labels = parts[0], parts[0].split(".")
    if len(dom) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(l) for l in labels) or labels[-1].isdigit():
        raise Invalid("REQ-4-2", f"bad domain: {dom!r}")
    if len(parts) == 2 and not NAME.fullmatch(parts[1]):
        raise Invalid("REQ-4-3", f"bad name: {parts[1]!r}")
    return dom, (parts[1] if len(parts) == 2 else None)


def is_gdid(d):
    try:
        parse_did(d)
        return True
    except Invalid:
        return False


def root_of(d):
    return "did:guardian:" + parse_did(d)[0]


def path_segment(d):
    return parse_did(d)[1] or "_"                 # REQ-4-5


_B58C = "[1-9A-HJ-NP-Za-km-z]+"
KEYREF = re.compile(f"did:key:(z{_B58C})#(z{_B58C})")
ATTREF = re.compile(f"did:guardian:([^?#:]+)\\?versionId=(z{_B58C})#key-(0|[1-9][0-9]*)")


def parse_keyref(vm):
    """REQ-5-11: did:key:<key>#<key>."""
    m = KEYREF.fullmatch(vm) if isinstance(vm, str) else None
    if not m or m.group(1) != m.group(2):
        raise Invalid("REQ-5-11", f"verificationMethod is not did:key:<key>#<key>: {str(vm)[:80]}")
    decode_key(m.group(1))
    return m.group(1)


def is_hash(h):
    try:
        return isinstance(h, str) and h[0] == "z" and b58dec(h[1:])[:2] == b"\x12\x20" and len(b58dec(h[1:])) == 34
    except Exception:
        return False


# ------------------------------------------------------------------- extensions (§7.11)
MINKEYS = "https://example.org/ext/min-keys"       # toy critical extension: policy.extensions[MINKEYS] = {"k": n}
IMPLEMENTED = frozenset({MINKEYS})
ABS_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9\-._~:/?\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")


class Unsupported(Exception):
    pass


def check_extensions(x, where):
    """REQ-7-29."""
    if not isinstance(x, dict):
        raise Invalid("REQ-7-29", f"{where}.extensions is not an object")
    for n in x:
        if not ABS_URI.fullmatch(n) or "#" in n:
            raise Invalid("REQ-7-29", f"extension name is not an absolute URI: {n!r}")


def check_minkeys(st, implemented, enforce_noncritical):
    """Toy extension min-keys. Its own rules (REQ-7-35): while critical, policy.extensions MUST carry
    {"k": n}, and the state MUST have at least n keys. Removing the configuration is invalid."""
    if MINKEYS not in implemented:
        return
    cfg = (st["policy"].get("extensions") or {}).get(MINKEYS)
    if MINKEYS not in st["critical"] and not enforce_noncritical:
        return                                     # REQ-7-34: MUST ignore (enforce_noncritical = non-conforming demo)
    if cfg is None:
        if MINKEYS in st["critical"]:
            raise Invalid("EXT-min-keys", "min-keys is critical but its configuration was removed")
        return
    if not (isinstance(cfg, dict) and set(cfg) == {"k"} and _is_k(cfg["k"]) and 1 <= cfg["k"] <= 8):
        raise Invalid("EXT-min-keys", "bad min-keys configuration")
    if len(st["keys"]) < cfg["k"]:
        raise Invalid("EXT-min-keys", f"min-keys requires {cfg['k']} keys")


# ------------------------------------------------------------------- values
def _nonchar(o):
    return 0xFDD0 <= o <= 0xFDEF or (o & 0xFFFE) == 0xFFFE


def check_values(v):
    """REQ-5-1 (I-JSON strings), REQ-5-2 (numbers)."""
    if isinstance(v, bool) or v is None:
        return
    if isinstance(v, float):
        if v != v or v != int(v):
            raise Invalid("REQ-5-2", f"number without an integer value {v!r}")
        v = int(v)
    if isinstance(v, int):
        if not 0 <= v <= MAX_INT:
            raise Invalid("REQ-5-2", f"integer out of range {v}")
    elif isinstance(v, str):
        for c in v:
            o = ord(c)
            if 0xD800 <= o <= 0xDFFF or _nonchar(o):
                raise Invalid("REQ-5-1", f"I-JSON forbids code point U+{o:04X}")
    elif isinstance(v, list):
        for x in v: check_values(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            check_values(k); check_values(x)
    else:
        raise Invalid("REQ-5-1", "not a JSON value")


MEMBERS = {   # type -> (required, optional, REQ for missing members)
    "create": ({"type", "did", "keys", "guardians", "successor", "policy", "services", "alsoKnownAs", "prev", "proof"}, set(), "REQ-7-7"),
    "update": ({"type", "keys", "services", "alsoKnownAs", "prev", "proof"}, set(), "REQ-7-10"),
    "addGuardian": ({"type", "entry", "prev", "proof"}, set(), "REQ-7-12"),
    "updateGuardian": ({"type", "guardian", "keys", "prev", "proof"}, set(), "REQ-7-15"),
    "removeGuardian": ({"type", "guardian", "prev", "proof"}, {"evidence"}, "REQ-7-17"),
    "setPolicy": ({"type", "policy", "successor", "prev", "proof"}, set(), "REQ-7-20"),
    "acceptWard": ({"type", "ward", "prev", "proof"}, set(), "REQ-7-22"),
    "releaseWard": ({"type", "ward", "prev", "proof"}, set(), "REQ-7-25"),
    "deactivate": ({"type", "prev", "proof"}, set(), "REQ-7-27"),
}
PROOF_MEMBERS = {"type", "cryptosuite", "verificationMethod", "proofPurpose", "proofValue"}
DEFAULT_DEACT = {"by": "both", "threshold": "majority"}
POLICY_MEMBERS = {"recovery", "membership", "removal", "deactivation", "orphan", "maxWards", "extensions"}


def check_keylist(keys, req="REQ-6-1", lo=1, hi=8):
    if not isinstance(keys, list) or not lo <= len(keys) <= hi:
        raise Invalid(req, f"key list must have {lo} to {hi} keys")
    for k in keys: decode_key(k)
    if len(set(keys)) != len(keys):
        raise Invalid(req, "duplicate key in a key list")


def check_entry(e):
    """REQ-6-2."""
    if not isinstance(e, dict) or set(e) != {"did", "anchor", "keys", "consent"}:
        raise Invalid("REQ-6-2", f"entry members {sorted(e) if isinstance(e, dict) else e!r}")
    if not is_gdid(e["did"]):
        raise Invalid("REQ-6-2", f"entry did {e['did']!r}")
    check_keylist(e["keys"], "REQ-6-2")
    if not is_hash(e["anchor"]) or not is_hash(e["consent"]):          # ASSUMPTION: only the format is checkable (REQ-8-2)
        raise Invalid("REQ-6-2", "consent is not an operation hash")


def check_ward(r):
    """REQ-6-4."""
    if not isinstance(r, dict) or set(r) != {"did", "anchor"} or not is_gdid(r["did"]) or not is_hash(r["anchor"]):
        raise Invalid("REQ-6-4", f"bad ward record {str(r)[:80]}")


def _is_k(v):
    # REQ-5-2: a number counts by its value, so 1.0 is the integer 1.
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and v == int(v)


def check_policy(p):
    """REQ-6-11, 6-12, 6-13 (+ REQ-5-3 for unknown members)."""
    if not isinstance(p, dict):
        raise Invalid("REQ-6-11", "policy is not an object")
    if set(p) - POLICY_MEMBERS:
        raise Invalid("REQ-5-3", f"unknown policy members {sorted(set(p) - POLICY_MEMBERS)}")
    for m, allowed in (("recovery", ("any", "majority", "all")), ("membership", ("majority", "all")), ("removal", ("any", "majority", "all"))):
        if m in p:
            if not ((isinstance(p[m], str) and p[m] in allowed) or _is_k(p[m])):
                raise Invalid("REQ-6-11", f"bad {m} value {p[m]!r}")
            if _is_k(p[m]) and not 1 <= p[m] <= 32:
                raise Invalid("REQ-6-13", f"{m} k={p[m]} not in 1..32")
    if "deactivation" in p:
        d = p["deactivation"]
        if not isinstance(d, dict) or set(d) != {"by", "threshold"}:
            raise Invalid("REQ-6-12", "deactivation must have exactly by and threshold")
        if not (isinstance(d["by"], str) and d["by"] in ("self", "guardians", "either", "both")):
            raise Invalid("REQ-6-12", f"bad deactivation.by {d['by']!r}")
        t = d["threshold"]
        if not ((isinstance(t, str) and t in ("majority", "all")) or _is_k(t)):
            raise Invalid("REQ-6-12", f"bad deactivation.threshold {t!r}")
        if _is_k(t) and not 1 <= t <= 32:
            raise Invalid("REQ-6-13", f"threshold k={t} not in 1..32")
    if "orphan" in p and p["orphan"] not in ("deactivate", "independent", "successor"):
        raise Invalid("REQ-6-11", f"bad orphan {p['orphan']!r}")
    if "maxWards" in p and not (_is_k(p["maxWards"]) and p["maxWards"] >= 1):
        raise Invalid("REQ-6-11", f"bad maxWards {p['maxWards']!r}")
    if "extensions" in p:
        check_extensions(p["extensions"], "policy")


def check_state(did, st):
    """REQ-6-7: state conforms to REQ-6-1..6-6 and the policy rules."""
    check_keylist(st["keys"])
    g = st["guardians"]
    if not isinstance(g, list) or len(g) > 32:
        raise Invalid("REQ-6-1", "guardians must be a list of 0 to 32 entries")
    for e in g: check_entry(e)
    if len({e["did"] for e in g}) != len(g):
        raise Invalid("REQ-6-1", "duplicate guardian DID")
    if st["successor"] is not None:
        check_entry(st["successor"])
    w = st["wards"]
    for r in w: check_ward(r)
    if len({r["did"] for r in w}) != len(w):
        raise Invalid("REQ-6-1", "duplicate ward DID")
    allk = list(st["keys"]) + [k for e in g for k in e["keys"]] + (st["successor"]["keys"] if st["successor"] else [])
    if len(set(allk)) != len(allk):
        raise Invalid("REQ-6-3", "a key appears more than once across keys, guardians and successor")
    if did in {e["did"] for e in g} | ({st["successor"]["did"]} if st["successor"] else set()) | {r["did"] for r in w}:
        raise Invalid("REQ-6-5", "identity names itself")
    if st["successor"] is not None and st["successor"]["did"] in {e["did"] for e in g}:
        raise Invalid("REQ-6-5", "successor is also a guardian")
    p = st["policy"]
    check_policy(p)
    if (p.get("orphan", "deactivate") == "successor") != (st["successor"] is not None):
        raise Invalid("REQ-6-14", "orphan must be 'successor' exactly when successor is an entry")
    if "maxWards" in p and len(w) > p["maxWards"]:
        raise Invalid("REQ-6-15", "wards exceeds maxWards")
    s = st["services"]
    if not isinstance(s, list) or len(s) > 32:
        raise Invalid("REQ-6-1", "services must be a list of 0 to 32 services")
    for x in s:
        if not isinstance(x, dict) or set(x) != {"id", "type", "serviceEndpoint"}:
            raise Invalid("REQ-6-6", f"service members {str(x)[:60]}")
        if not (isinstance(x["id"], str) and FRAGMENT.fullmatch(x["id"])):
            raise Invalid("REQ-6-6", f"service id {x['id']!r}")
        if not isinstance(x["type"], str):
            raise Invalid("REQ-6-6", "service type must be a string")
        if not (isinstance(x["serviceEndpoint"], str) and URI.fullmatch(x["serviceEndpoint"])):
            raise Invalid("REQ-6-6", f"serviceEndpoint {str(x['serviceEndpoint'])[:60]}")
    if len({x["id"] for x in s}) != len(s):
        raise Invalid("REQ-6-1", "duplicate service id")
    a = st["alsoKnownAs"]
    if not isinstance(a, list) or len(a) > 32 or not all(isinstance(x, str) and URI.fullmatch(x) for x in a) or len(set(a)) != len(a):
        raise Invalid("REQ-6-1", "alsoKnownAs must be 0 to 32 distinct URIs")
    if len(set(st["critical"])) != len(st["critical"]):
        raise Invalid("REQ-6-1", "state critical names are not distinct (REQ-7-32 appends; see FINDINGS-r5 X-4)")


# ------------------------------------------------------------- approvals
def required(setting, v, N, E):
    """REQ-6-8."""
    if v == "any": r = 1
    elif v == "majority": r = E // 2 + 1
    elif v == "all": r = E
    else: r = min(v, E)
    if v != "any" and N >= 2: r = max(r, 2)
    if setting in ("membership", "deactivation"): r = max(r, N // 2 + 1)
    return r


def pol(st, m):
    return st["policy"].get(m, DEFAULT_DEACT if m == "deactivation" else "majority")


def eval_rule(op, before, S, force=False):
    """REQ-7-6 with REQ-6-9. S = set of keys with valid proofs. Returns (ok, impossible_clause_had_signers)."""
    t = op["type"]
    kb = set(before["keys"]) if before else set()
    G = before["guardians"] if before else []
    N = len(G)
    one_key = bool(S & kb)
    appr = lambda e: bool(S & set(e["keys"]))               # REQ-5-16
    every = lambda ks: set(ks) <= S
    flag = [False]

    def gper(setting, v, eligible):
        E, cnt = len(eligible), sum(1 for e in eligible if appr(e))
        r = required(setting, v, N, E)
        if E == 0 or r > E:                                  # REQ-6-9
            flag[0] = flag[0] or cnt > 0
            return force
        return cnt >= r

    if t == "create":
        ok = every(op["keys"]) and all(every(e["keys"]) for e in op["guardians"]) and (op["successor"] is None or every(op["successor"]["keys"]))
    elif t == "update":
        ok = every(op["keys"]) and (one_key or gper("recovery", pol(before, "recovery"), G))
    elif t == "addGuardian":
        ok = every(op["entry"]["keys"]) and one_key and (N == 0 or gper("membership", pol(before, "membership"), G))
    elif t == "updateGuardian":
        cur = next((e for e in G if e["did"] == op["guardian"]), None) or before["successor"]
        others = [e for e in G if e["did"] != op["guardian"]]
        ok = every(op["keys"]) and (appr(cur) or (one_key and any(appr(e) for e in others)))
    elif t == "removeGuardian":
        cur = next(e for e in G if e["did"] == op["guardian"])
        others = [e for e in G if e["did"] != op["guardian"]]
        suc = before["successor"]
        # ASSUMPTION: gper is evaluated first so that REQ-6-9 is reported when it is the only blocker
        ok = (gper("removal", pol(before, "removal"), others) or (appr(cur) and N >= 2)
              or ("evidence" in op and one_key)
              or (N == 1 and suc is not None and one_key and appr(suc)))
    elif t == "setPolicy":
        ns = op["successor"]
        ok = one_key and (N == 0 or gper("membership", pol(before, "membership"), G)) and (ns is None or ns == before["successor"] or every(ns["keys"]))
    elif t in ("acceptWard", "releaseWard"):
        ok = one_key or gper("recovery", pol(before, "recovery"), G)
    else:
        if N == 0:
            ok = one_key
        else:
            d = pol(before, "deactivation")
            gp = lambda: gper("deactivation", d["threshold"], G)
            ok = {"self": lambda: one_key, "guardians": gp, "either": lambda: one_key or gp(), "both": lambda: one_key and gp()}[d["by"]]()
    return ok, flag[0]


def permitted_keys(op, before):
    """REQ-7-5."""
    s = set()
    if before:
        s |= set(before["keys"]) | {k for e in before["guardians"] for k in e["keys"]}
        if before["successor"]: s |= set(before["successor"]["keys"])
    if isinstance(op.get("keys"), list): s |= set(op["keys"])
    for e in (op.get("guardians") or []) + [op.get("entry"), op.get("successor")]:
        if isinstance(e, dict) and isinstance(e.get("keys"), list): s |= set(e["keys"])
    return s


# ------------------------------------------------------------- state transition
def apply(op, st):
    t = op["type"]
    if t == "create":
        return {"keys": op["keys"], "guardians": copy.deepcopy(op["guardians"]), "successor": copy.deepcopy(op["successor"]),
                "wards": [], "policy": op["policy"], "services": op["services"], "alsoKnownAs": op["alsoKnownAs"], "deactivated": False,
                "critical": list(op.get("critical", []))}
    st = copy.deepcopy(st)
    st["critical"] = st["critical"] + [n for n in op.get("critical", []) if n not in st["critical"]]   # REQ-7-32 (union)
    if t == "update":
        st.update(keys=op["keys"], services=op["services"], alsoKnownAs=op["alsoKnownAs"])
    elif t == "addGuardian":
        st["guardians"].append(copy.deepcopy(op["entry"]))
    elif t == "updateGuardian":
        for e in st["guardians"] + ([st["successor"]] if st["successor"] else []):
            if e["did"] == op["guardian"]:
                e["keys"] = list(op["keys"])
    elif t == "removeGuardian":
        had = bool(st["guardians"])
        st["guardians"] = [e for e in st["guardians"] if e["did"] != op["guardian"]]
        if had and not st["guardians"]:                       # REQ-6-10
            o = st["policy"].get("orphan", "deactivate")
            if o == "deactivate":
                st["deactivated"] = True
            elif o == "successor":
                st["guardians"], st["successor"] = [st["successor"]], None
                st["policy"] = dict(st["policy"], orphan="deactivate")
    elif t == "setPolicy":
        st["policy"], st["successor"] = op["policy"], copy.deepcopy(op["successor"])
    elif t == "acceptWard":
        st["wards"].append(dict(op["ward"]))
    elif t == "releaseWard":
        st["wards"] = [r for r in st["wards"] if r["did"] != op["ward"]]
    elif t == "deactivate":
        st["deactivated"] = True
    return st


def check_op(did, op, idx, before, implemented=IMPLEMENTED, enforce_noncritical=False):
    # ---- 5.1 conformance to Sections 5 and 7
    check_values(op)
    if not all(m in op for m in ("type", "prev", "proof")):
        raise Invalid("REQ-7-1", "missing type, prev or proof")
    t = op["type"]
    if not isinstance(t, str):
        raise Invalid("REQ-7-2", f"type is not a string")
    if t not in MEMBERS:
        raise Unsupported(f"unknown type {t!r}")            # REQ-8-1
    if (t == "create") != (idx == 0):
        raise Invalid("REQ-7-3", "create must be first and only first")
    req_m, opt_m, mreq = MEMBERS[t]
    if t == "create":
        if did != root_of(did): req_m = req_m | {"attestation"}
        # REQ-7-7: a root create MUST NOT carry an attestation
    if not req_m <= set(op):
        raise Invalid(mreq, f"missing members {sorted(req_m - set(op))}")
    opt_m = opt_m | {"extensions", "critical"}
    if set(op) - req_m - opt_m:
        raise Invalid("REQ-5-3", f"extra members {sorted(set(op) - req_m - opt_m)}")
    if "extensions" in op:
        check_extensions(op["extensions"], "operation")
    if "critical" in op:
        if t not in ("create", "setPolicy"):
            raise Invalid("REQ-7-30", f"critical is not allowed on {t}")
        c = op["critical"]
        if not isinstance(c, list) or not c or len(set(map(str, c))) != len(c) or not all(isinstance(n, str) for n in c):
            raise Invalid("REQ-7-30", "critical must be a non-empty list of distinct names")
        avail = set((op.get("policy") or {}).get("extensions") or {} if isinstance(op.get("policy"), dict) else {})   # REQ-7-30 (final)
        for n in c:
            if n not in avail:
                raise Invalid("REQ-7-30", f"critical names an absent extension {n}")
    if t == "create" and op["prev"] is not None:
        raise Invalid("REQ-7-4", "create prev must be null")
    if "keys" in op:
        check_keylist(op["keys"])
    G = [e["did"] for e in before["guardians"]] if before else []
    if t == "create":
        if not isinstance(op["guardians"], list):
            raise Invalid("REQ-6-1", "guardians must be a list")
        for e in op["guardians"]: check_entry(e)
        if op["successor"] is not None: check_entry(op["successor"])
        if not isinstance(op["policy"], dict):
            raise Invalid("REQ-6-11", "policy must be an object")
        if "attestation" in op:
            a = op["attestation"]
            if not isinstance(a, dict) or set(a) != PROOF_MEMBERS or a["type"] != "DataIntegrityProof" or a["proofPurpose"] != "capabilityInvocation":
                raise Invalid("REQ-7-9", "attestation is not a Data Integrity proof as in REQ-5-11")
            if not isinstance(a["cryptosuite"], str) or not isinstance(a["proofValue"], str):
                raise Invalid("REQ-7-9", "attestation cryptosuite/proofValue")   # value judged at resolution (REQ-11-2), see FINDINGS-r6
            m = ATTREF.fullmatch(a["verificationMethod"]) if isinstance(a["verificationMethod"], str) else None
            if not m or m.group(1) != parse_did(did)[0]:
                raise Invalid("REQ-7-9", "attestation verificationMethod must name the root identity of the DID's domain")
    if t == "addGuardian":
        check_entry(op["entry"])
        if op["entry"]["did"] in G:
            raise Invalid("REQ-7-13", "already a guardian")
    sdid = before["successor"]["did"] if before and before["successor"] else None
    if t == "updateGuardian" and op["guardian"] not in G + ([sdid] if sdid else []):
        raise Invalid("REQ-7-15", "guardian is not a current guardian or the successor")
    if t == "removeGuardian" and op["guardian"] not in G:
        raise Invalid("REQ-7-17", "guardian is not a current guardian")
    if t == "removeGuardian" and "evidence" in op and not is_hash(op["evidence"]):
        raise Invalid("REQ-7-18", "evidence is not an operation hash")       # all a verifier can check
    if t == "setPolicy":
        if op["successor"] is not None: check_entry(op["successor"])
    if t == "acceptWard":
        check_ward(op["ward"])
        if op["ward"]["did"] in {r["did"] for r in before["wards"]}:
            raise Invalid("REQ-7-23", "ward already recorded")
    if t == "releaseWard" and op["ward"] not in {r["did"] for r in before["wards"]}:
        raise Invalid("REQ-7-25", "ward is not in wards")
    proofs = op["proof"]
    if not isinstance(proofs, list):
        raise Invalid("REQ-5-10", "proof must be an array")
    vms = [p.get("verificationMethod") if isinstance(p, dict) else None for p in proofs]
    if all(isinstance(x, str) for x in vms) and vms != sorted(vms):
        raise Invalid("REQ-5-10", "proofs are not sorted by verificationMethod")
    signers = []
    for p in proofs:
        if not isinstance(p, dict):
            raise Invalid("REQ-5-10", "proof entry is not an object")
        if set(p) != PROOF_MEMBERS or p["type"] != "DataIntegrityProof" or p["proofPurpose"] != "capabilityInvocation":
            raise Invalid("REQ-5-11", f"proof members/type/purpose {sorted(p)}")
        if p["cryptosuite"] != "ecdsa-jcs-2019" or not isinstance(p["proofValue"], str):
            raise Invalid("REQ-5-12", f"cryptosuite {p['cryptosuite']!r}")
        k = parse_keyref(p["verificationMethod"])
        if k in signers:
            raise Invalid("REQ-5-15", f"two proofs from {k[:20]}...")
        signers.append(k)
    # ---- 5.2 proofs valid, from permitted keys
    allowed = permitted_keys(op, before)
    doc = {k: v for k, v in op.items() if k not in ("proof", "attestation")}
    for p, k in zip(proofs, signers):
        if k not in allowed:
            raise Invalid("REQ-7-5", f"proof from a key that is not permitted: {k[:20]}...")
        verify_jcs(decode_key(k), doc, p, "REQ-5-14")
    # ---- 5.3 approvals
    S = set(signers)
    ok, imp = eval_rule(op, before, S)
    if not ok:
        if imp and eval_rule(op, before, S, force=True)[0]:
            raise Invalid("REQ-6-9", f"{t}: guardian clause cannot be met (E = 0 or required > E)")
        raise Invalid("REQ-7-6", f"{t}: required approvals missing")
    # ---- 5.4 apply and check Section 6
    after = apply(op, before)
    check_state(did, after)
    check_minkeys(after, implemented, enforce_noncritical)                       # REQ-7-33
    return after


def op_unsupported(op, before, implemented):
    """REQ-8-1: is this operation unsupported?"""
    t = op.get("type")
    if isinstance(t, str) and t not in MEMBERS:
        return f"unknown type {t!r}"
    for n in (before["critical"] if before else []):
        if n not in implemented:
            return f"state critical names {n}"
    c = op.get("critical")
    for n in (c if isinstance(c, list) else []):
        if isinstance(n, str) and n not in implemented:
            return f"critical extension not implemented: {n}"
    for p in op.get("proof", []) if isinstance(op.get("proof"), list) else []:
        if isinstance(p, dict) and isinstance(p.get("cryptosuite"), str) and p["cryptosuite"] != "ecdsa-jcs-2019":
            return f"cryptosuite not implemented: {p['cryptosuite']}"
    return None


def verify_log(did, log, implemented=IMPLEMENTED, enforce_noncritical=False):
    """REQ-8-1. Depends only on the log (REQ-8-2). Returns states after each operation."""
    parse_did(did)
    if not isinstance(log, list) or not log:
        raise Invalid("REQ-8-1", "log must be a non-empty array")
    for op in log:
        if not isinstance(op, dict):
            raise Invalid("REQ-5-1", "operation is not a JSON object")
    hs = [op_hash(op) for op in log]
    states, st = [], None
    for i, op in enumerate(log):
        # ASSUMPTION: within one operation, the unsupported test comes before the steps (FINDINGS-r6 Y-2)
        u = op_unsupported(op, st, implemented)
        if u:
            raise Unsupported(f"op {i}: {u}")
        if i == 0:
            if op.get("type") != "create":
                raise Invalid("REQ-7-3", "first operation is not a create")
            if op.get("did") != did:
                raise Invalid("REQ-8-1", "create.did does not equal the DID")
        elif op.get("prev") != hs[i - 1]:
            raise Invalid("REQ-7-4", f"operation {i}: prev does not match")
        if st is not None and st["deactivated"]:
            raise Invalid("REQ-8-1", f"operation {i} follows a deactivated state")
        try:
            st = check_op(did, op, i, st, implemented, enforce_noncritical)
        except Invalid as e:
            raise Invalid(e.req, f"op {i} ({op.get('type')}): {e.msg}")
        states.append(st)
    return states


# ------------------------------------------------------------- public API
def did_document(did, st):
    """REQ-9-2, 9-3."""
    if st["deactivated"]:
        return {"@context": list(CTX), "id": did}
    ids = [f"{did}#key-{n}" for n in range(len(st["keys"]))]
    doc = {"@context": list(CTX), "id": did,
           "verificationMethod": [{"id": i, "type": "Multikey", "controller": did, "publicKeyMultibase": k} for i, k in zip(ids, st["keys"])],
           "authentication": list(ids), "assertionMethod": list(ids), "capabilityInvocation": list(ids),
           "service": [dict(s, id=did + s["id"]) for s in st["services"]]}
    if st["alsoKnownAs"]:
        doc["alsoKnownAs"] = list(st["alsoKnownAs"])
    return doc


def verify(did, log, implemented=IMPLEMENTED, enforce_noncritical=False):
    try:
        states = verify_log(did, log, implemented, enforce_noncritical)
    except Unsupported as e:
        return {"valid": False, "result": "unsupported", "req": "REQ-8-1", "message": str(e)}
    except Invalid as e:
        return {"valid": False, "result": "invalid", "req": e.req, "message": e.msg}
    st, vid = states[-1], op_hash(log[-1])
    meta = {"versionId": vid, "anchor": anchor_of(log)}          # REQ-9-4
    if st["deactivated"]:
        meta["deactivated"] = True
    return {"valid": True, "result": "valid", "req": None, "state": st, "states": states, "anchor": anchor_of(log), "versionId": vid,
            "didDocument": did_document(did, st), "didDocumentMetadata": meta}


def resolve_version(did, log, version):
    """REQ-9-5. ASSUMPTION: only the prefix up to `version` must verify."""
    hs = [op_hash(o) for o in log] if isinstance(log, list) else []
    if version not in hs:
        return {"valid": False, "req": "REQ-9-5", "message": "no such version"}
    return verify(did, log[:hs.index(version) + 1])


# ------------------------------------------------------------- §11 resolution
def verify_attestation(did, log, resolver):
    """REQ-11-2. Returns (ok, reason)."""
    if did == root_of(did):
        return True, "root identity: no attestation"
    a = log[0].get("attestation")
    if isinstance(a, dict) and a.get("cryptosuite") != "ecdsa-jcs-2019":
        return None, "REQ-11-2: attestation cryptosuite not implemented (unsupported)"
    m = ATTREF.fullmatch(a.get("verificationMethod", "")) if isinstance(a, dict) else None
    if not m:
        return False, "REQ-7-9: malformed attestation"
    root, version, n = root_of(did), m.group(2), int(m.group(3))
    rlog = resolver.get(root)
    if rlog is None:
        return False, "REQ-11-2: root log unavailable"
    hs = [op_hash(o) for o in rlog]
    if version not in hs:
        return False, "REQ-11-2: root log lacks the named version"
    r = verify(root, rlog[:hs.index(version) + 1])
    if not r["valid"]:
        return False, f"REQ-11-2: root log prefix does not verify ({r['req']})"
    if r["state"]["deactivated"]:
        return False, "REQ-11-2: root state is deactivated at that version"
    keys = r["state"]["keys"]
    if n >= len(keys):
        return False, "REQ-11-2: no key at that index"
    try:
        verify_jcs(decode_key(keys[n]), {k: v for k, v in log[0].items() if k not in ("proof", "attestation")}, a, "REQ-11-2")
    except Invalid as e:
        return False, f"{e.req}: {e.msg}"
    return True, "valid"


def fetch_verified(d, resolver):
    l = resolver.get(d)
    r = verify(d, l) if l is not None else None
    return (l, r) if r and r["valid"] else (None, None)


def mutuality(did, state, anchor, resolver):
    """REQ-11-5: first matching result per entry."""
    out = []
    ents = [("guardian", e) for e in state["guardians"]] + ([("successor", state["successor"])] if state["successor"] else [])
    for role, e in ents:
        l, r = fetch_verified(e["did"], resolver)
        rec = {"did": did, "anchor": anchor}
        if not l: res = "unavailable"
        elif r["anchor"] != e["anchor"]: res = "different identity"
        elif r["state"]["deactivated"]: res = "deactivated"
        elif not _is_guard_for(l, e["consent"], rec) or rec not in r["state"]["wards"]: res = "withdrawn"
        elif not keys_eq(r["state"]["keys"], e["keys"]): res = "keys out of date"
        else: res = "mutual"
        out.append((role, e["did"], res))
    return out


def _is_guard_for(log, h, rec):
    g = next((o for o in log if op_hash(o) == h), None)
    return bool(g) and g.get("type") == "acceptWard" and g.get("ward") == rec


def ward_reports(did, state, resolver):
    """REQ-11-6: first matching result per ward record."""
    out = []
    for rec in state["wards"]:
        l, r = fetch_verified(rec["did"], resolver)
        if not l: res = "unavailable"
        elif r["anchor"] != rec["anchor"]: res = "different identity"
        elif did in [e["did"] for e in r["state"]["guardians"]]: res = "guardian"
        elif r["state"]["successor"] and r["state"]["successor"]["did"] == did: res = "successor"
        else: res = "not related"
        out.append((rec["did"], res))
    return out


def resolve(did, log, resolver):
    """REQ-11-1 + REQ-11-5..11-7."""
    r = verify(did, log)
    if not r["valid"]:
        return r
    r["attestation"] = verify_attestation(did, log, resolver)
    if r["attestation"][0] is None:
        return {"valid": False, "result": "unsupported", "req": "REQ-11-2", "message": r["attestation"][1]}
    if not r["attestation"][0]:
        return {"valid": False, "result": "invalid", "req": "REQ-11-2", "message": r["attestation"][1]}
    r["mutuality"] = mutuality(did, r["state"], r["anchor"], resolver)
    r["wardReports"] = ward_reports(did, r["state"], resolver)
    r["guardianships"] = [d for role, d, res in r["mutuality"] if res in ("mutual", "keys out of date")]   # REQ-11-7
    return r


class Resolver:
    """REQ-11-3, 11-4."""

    def __init__(self):
        self.seen = {}

    def fetch(self, did, log):
        warn = []
        if isinstance(log, list) and log:
            a, hs = anchor_of(log), [op_hash(o) for o in log]
            if did in self.seen:
                ra, rv = self.seen[did]
                if ra != a: warn.append("different identity")
                elif rv not in hs: warn.append("rolled back or forked")
            if not warn: self.seen[did] = (a, hs[-1])
        return warn


# ------------------------------------------------------------- §10 registrar
def standing(e, did, anchor, resolver, skip_keys=False):
    """REQ-10-6. Returns None if the entry has standing for (did, anchor), else the failing item."""
    l, r = fetch_verified(e["did"], resolver)
    if not l: return "log cannot be fetched or does not verify"
    if r["anchor"] != e["anchor"]: return "item 1: anchor differs"
    if r["state"]["deactivated"]: return "item 2: deactivated"
    if not skip_keys and not keys_eq(r["state"]["keys"], e["keys"]): return "item 3: keys differ"
    rec = {"did": did, "anchor": anchor}
    if not _is_guard_for(l, e["consent"], rec): return "item 4: consent is not a guard naming this identity"
    if rec not in r["state"]["wards"]: return "item 5: record not in wards"
    return None


def registrar_checks(did, log, op, resolver):
    """REQ-10-7 table. Returns None if every applicable check holds, else a reason."""
    t = op.get("type")
    anchor = anchor_of(log if log else [op])
    before = verify(did, log)["state"] if log else None
    after = verify(did, log + [op])["state"]
    S = {p["verificationMethod"].split("#")[1] for p in op.get("proof", [])}
    # row 1: an operation adds or replaces an entry
    new = []
    if t == "create":
        new = list(op["guardians"]) + ([op["successor"]] if op["successor"] else [])
    elif t == "addGuardian":
        new = [op["entry"]]
    elif t == "updateGuardian":
        new = [next(e for e in after["guardians"] + ([after["successor"]] if after["successor"] else []) if e["did"] == op["guardian"])]
    elif t == "setPolicy" and op["successor"] is not None and not _entry_eq(op["successor"], before["successor"]):
        new = [op["successor"]]
    for e in new:
        why = standing(e, did, anchor, resolver)
        if why: return f"row 1: new entry for {e['did']} lacks standing ({why})"
    # row 2: a guardian or successor approves
    if before:
        for e in before["guardians"] + ([before["successor"]] if before["successor"] else []):
            if S & set(e["keys"]):
                skip = t == "updateGuardian" and op["guardian"] == e["did"]
                why = standing(e, did, anchor, resolver, skip_keys=skip)
                if why: return f"row 2: approving {e['did']} lacks standing ({why})"
    # row 3
    if t == "updateGuardian":
        l, r = fetch_verified(op["guardian"], resolver)
        if not l or not keys_eq(r["state"]["keys"], op["keys"]): return "row 3: new keys are not the guardian's current keys"
    # row 4
    if t == "removeGuardian" and "evidence" in op:
        e = next(x for x in before["guardians"] if x["did"] == op["guardian"])
        l, r = fetch_verified(op["guardian"], resolver)
        if not l or r["anchor"] != e["anchor"]: return "row 4: guardian log unavailable or anchor differs"
        hs = [op_hash(o) for o in l]
        gi = hs.index(op["evidence"]) if op["evidence"] in hs else None
        ci = hs.index(e["consent"]) if e["consent"] in hs else None
        g = l[gi] if gi is not None else None
        ok = g is not None and (g.get("type") == "deactivate" or (g.get("type") == "releaseWard" and g.get("ward") == did))
        if not ok: return "row 4: evidence is not a deactivate or a releaseWard of this identity in that log"
        if ci is None or gi <= ci: return "row 4: evidence does not follow the entry's consent"
        rec = {"did": did, "anchor": anchor}
        if not (r["state"]["deactivated"] or rec not in r["state"]["wards"]):
            return "row 4: the entry does not lack standing because of item 2 or item 5"
    # row 5: promotion
    if t == "removeGuardian" and before["successor"] and not after["successor"] and after["guardians"]:
        why = standing(before["successor"], did, anchor, resolver)
        if why: return f"row 5: promoted successor lacks standing ({why})"
    # row 6
    if t == "acceptWard" and op["ward"]["did"] in resolver:
        wl = resolver[op["ward"]["did"]]
        if isinstance(wl, list) and wl and anchor_of(wl) != op["ward"]["anchor"]: return "row 6: ward record does not name the ward's anchor"
    return None


def _entry_eq(a, b):
    if a is None or b is None: return a is b
    return a["did"] == b["did"] and a["anchor"] == b["anchor"] and a["consent"] == b["consent"] and keys_eq(a["keys"], b["keys"])


def registrar_accept(did, log, op, resolver, registrar_domain=None, used_names=(), accepted_prevs=(), implemented=IMPLEMENTED):
    """REQ-10-5, 10-7, 10-8, 10-9."""
    log = log or []
    if not isinstance(op, dict):
        return {"accepted": False, "req": "REQ-10-5", "message": "not an object"}
    if log:
        if op.get("prev") != op_hash(log[-1]):
            return {"accepted": False, "req": "REQ-10-5", "message": "prev is not the version of the log"}
    elif op.get("type") != "create":
        return {"accepted": False, "req": "REQ-10-5", "message": "no log and not a create"}
    if log and op.get("prev") in accepted_prevs:
        return {"accepted": False, "req": "REQ-10-8", "message": "an operation with this prev was already accepted"}
    if op.get("type") == "create":
        if registrar_domain is not None and (parse_did(did)[0] != registrar_domain or path_segment(did) in used_names):
            return {"accepted": False, "req": "REQ-10-9", "message": "wrong domain or name used"}
        if did != root_of(did):
            m = ATTREF.fullmatch(op.get("attestation", {}).get("verificationMethod", ""))
            rl = resolver.get(root_of(did))
            if not m or not rl or op_hash(rl[-1]) != m.group(2):
                return {"accepted": False, "req": "REQ-10-9", "message": "attestation does not use the root's current version"}
    res = verify(did, log + [op], implemented)
    if not res["valid"]:
        return {"accepted": False, "req": "REQ-10-5", "message": f"appended log is {res['result']}: {res['req']} {res['message']}"}
    if op.get("type") == "create" and did != root_of(did) and not verify_attestation(did, [op], resolver)[0]:
        return {"accepted": False, "req": "REQ-10-9", "message": "attestation invalid"}
    why = registrar_checks(did, log, op, resolver)
    if why:
        return {"accepted": False, "req": "REQ-10-7", "message": why}
    return {"accepted": True, "req": None, "message": "ok"}
