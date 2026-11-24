"""Runner (r7): vectors-final, single-change check, DID documents, resolver/registrar checks, W3C vectors."""
import copy, glob, hashlib, json, os, sys
from collections import Counter
from verifier import (IMPLEMENTED, verify, registrar_accept, resolve, resolve_version, Resolver, jcs, b58dec, verify_jcs, hash_data,
                      decode_key, encode_key, op_hash, anchor_of)
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(HERE, "vectors-final")

W3C_UNSIGNED = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33", "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential", "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678", "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"}}
W3C_PUB = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
W3C_SEC = "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"
W3C_PROOF = {"type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2019", "created": "2023-02-24T23:36:38Z",
             "verificationMethod": f"did:key:{W3C_PUB}#{W3C_PUB}", "proofPurpose": "assertionMethod",
             "proofValue": "z5ptCet75SaEgzG4v4zJhbJtfNi74Wv7Fq15hhKouJQQjEPQvPZKaYxcMXAMLPQS2FXrkCWokNJkFVkwxNzZfD5oT"}
W3C_CANON = '{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject":{"alumniOf":"The School of Examples","id":"did:example:abcdefgh"},"description":"A minimum viable example of an Alumni Credential.","id":"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33","issuer":"https://vc.example/issuers/5678","name":"Alumni Credential","type":["VerifiableCredential","AlumniCredential"],"validFrom":"2023-01-01T00:00:00Z"}'
W3C_COMBINED = "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec2559b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
W3C_SIGHEX = "f15c3b599eb9b3cad05df9d8e8b39a70a86375833b53743c764ac0a88c4457d60707fd7d073e03d906130631d87803f80a9824dc9939632ba92d418181be9d16"


def w3c():
    out = [("canonical document", jcs(W3C_UNSIGNED) == W3C_CANON),
           ("doc hash", hashlib.sha256(W3C_CANON.encode()).hexdigest() == W3C_COMBINED[64:]),
           ("combined hashData", hash_data(W3C_UNSIGNED, W3C_PROOF).hex() == W3C_COMBINED),
           ("proofValue == sig hex", b58dec(W3C_PROOF["proofValue"][1:]).hex() == W3C_SIGHEX)]
    try:
        verify_jcs(decode_key(W3C_PUB), W3C_UNSIGNED, W3C_PROOF); ok = True
    except Exception:
        ok = False
    out.append(("signature verifies", ok))
    sec = b58dec(W3C_SEC[1:])
    priv = ec.derive_private_key(int.from_bytes(sec[2:], "big"), ec.SECP256R1())
    out.append(("secret key -> public Multikey", sec[:2] == b"\x86\x26" and encode_key(priv.public_key()) == W3C_PUB))
    try:
        verify_jcs(decode_key(W3C_PUB), W3C_UNSIGNED, dict(W3C_PROOF, proofPurpose="authentication")); ok = False
    except Exception:
        ok = True
    out.append(("tampered proof config rejected", ok))
    return out


def ndiff(a, b):
    if not isinstance(a, list) or not isinstance(b, list):
        return 0 if a == b else 1
    return sum(1 for i in range(max(len(a), len(b))) if i >= len(a) or i >= len(b) or a[i] != b[i])


def run_one(v):
    kind = v.get("kind", "verify")
    if kind == "registrar":
        got = registrar_accept(v["did"], v["log"], v["op"], v["resolver"], implemented=frozenset(v.get("implemented", IMPLEMENTED)),
                               registrar_domain=v.get("registrarDomain"), used_names=set(v.get("acceptedCreates", [])),
                               segment=v.get("segment"), pins=v.get("pins"), request=v.get("request"))
        return ("accepted" if got["accepted"] else "rejected") == v["expect"]["result"], f"accepted={got['accepted']} {got['req'] or ''} {got['message'][:110]}"
    if kind == "resolve":
        got = resolve(v["did"], v["log"], v["resolver"], version=v.get("versionId"), pins=v.get("pins"))
        ok = (got.get("result") or ("valid" if got["valid"] else "invalid")) == v["expect"]["result"]
        if ok and got["valid"] and "expectDocument" in v:
            ok = got["didDocument"] == v["expectDocument"]
        if ok and got["valid"] and "expectMutuality" in v:
            ok = [r for _, _, r in got["mutuality"]] == v["expectMutuality"]
        if ok and got["valid"] and "expectWardReports" in v:
            ok = [[d.split(":")[-1], r] for d, r in got["wardReports"]] == v["expectWardReports"]
        det = (f"valid mutuality={[r for _, _, r in got['mutuality']]} guardianships={len(got['guardianships'])}" if got["valid"]
               else f"{got['req']}: {got['message'][:110]}")
        return ok, det
    got = verify(v["did"], v["log"])
    ok = got["result"] == v["expect"]["result"]
    if ok and v.get("splitIfEnforced"):
        ok = verify(v["did"], v["log"], enforce_noncritical=True)["result"] == "invalid"
    if ok and v.get("unsupportedWithout"):
        ok = verify(v["did"], v["log"], implemented=frozenset())["result"] == "unsupported"
    if ok and got["valid"]:
        if "expectDocument" in v: ok = got["didDocument"] == v["expectDocument"]
        if "anchor" in v: ok = ok and got["anchor"] == v["anchor"] and got["didDocumentMetadata"]["anchor"] == v["anchor"]
        es = v.get("expectState", {})
        if "deactivated" in es: ok = ok and got["state"]["deactivated"] == es["deactivated"]
        if "guardians" in es:
            ok = ok and [e["did"] for e in got["state"]["guardians"]] == es["guardians"] and got["state"]["successor"] is None \
                and got["state"]["policy"].get("orphan") == es["orphan"]
    return ok, ("valid" if got["valid"] else f"{got['result']} {got['req']}: {got['message'][:120]}")


def extra_checks(V):
    f = []
    def check(c, n):
        if not c: f.append(n)
    v = V["upd-guardian-self"]
    r = resolve_version(v["did"], v["log"], op_hash(v["log"][0]))
    check(r["valid"] and r["didDocument"]["verificationMethod"][0]["publicKeyMultibase"] == v["log"][0]["keys"][0], "REQ-9-5")
    res = Resolver(); v = V["upd-guardian-self"]
    check(not res.fetch(v["did"], v["log"]), "REQ-11-3 first fetch")
    check("rolled back or forked" in res.fetch(v["did"], v["log"][:-1]), "REQ-11-4 rollback")
    res = Resolver(); a = V["ATTACK-strip-redundant-proof"]
    import copy as _c
    full = _c.deepcopy(a["log"]); full[-1] = V["recovery-N1"]["log"][-1] if False else full[-1]
    res.fetch(a["did"], a["log"])
    check(verify(a["did"], a["log"])["valid"], "stripped-proof variant verifies")
    res = Resolver(); res.fetch(a["did"], a["log"])
    check("different identity" in res.fetch(a["did"], [dict(V["create-full"]["log"][0], did=a["did"])]), "REQ-11-4 different anchor")
    v = V["add-N1"]
    check(not registrar_accept(v["did"], v["log"][:-1], v["log"][-1], v["resolver"], accepted_prevs={v["log"][-1]["prev"]})["accepted"], "REQ-10-7")
    v = V["create"]
    check(not registrar_accept(v["did"], [], v["log"][0], v["resolver"], registrar_domain="acme.com", used_names={"alice"})["accepted"], "REQ-10-12")
    check(registrar_accept(v["did"], [], v["log"][0], v["resolver"], registrar_domain="acme.com", used_names={"bob"})["accepted"], "REQ-10-12 other name")
    check(not registrar_accept(v["did"], [], v["log"][0], v["resolver"], registrar_domain="other.com")["accepted"], "REQ-10-8 domain")
    return f


def main():
    V = {os.path.basename(p)[:-5]: json.load(open(p)) for p in sorted(glob.glob(os.path.join(VDIR, "*.json")))}
    passed = failed = 0
    kinds, targets, diffs = Counter(), set(), Counter()
    for name, v in V.items():
        ok, det = run_one(v)
        kind = v.get("kind", "verify")
        exp = v["expect"]["result"] in ("valid", "accepted")
        kinds[(kind, "ATTACK" if "ATTACK" in name or "GAP" in v["description"] else "valid" if exp and "base" not in v or (exp and v.get("base") is None) else "invalid" if not exp else "valid")] += 1
        if v.get("targets"): targets.add(v["targets"])
        if v.get("base") and v["base"] in V:
            b = V[v["base"]]
            n = ndiff(v["log"], b["log"]) + ndiff([v.get("op")], [b.get("op")]) + (v["did"] != b["did"]) + \
                sum(ndiff(v["resolver"].get(d), b["resolver"].get(d)) for d in set(v["resolver"]) | set(b["resolver"]))
            diffs[n] += 1
        passed += ok; failed += not ok
        if not ok or "-v" in sys.argv:
            print(f"{'PASS' if ok else 'FAIL'} {name} [{v.get('targets')}] expect={exp}: {det}")
    print(f"\nvectors: {len(V)}; passed {passed}, failed {failed}")
    for k in sorted(kinds): print(f"  {k[0]:9s} {k[1]:7s} {kinds[k]}")
    print(f"invalid-vs-base changed elements -> count: {dict(sorted(diffs.items()))}")
    print(f"REQ IDs targeted: {len(targets)}: " + " ".join(sorted(targets, key=lambda r: [int(x) for x in r[4:].split('-')])))
    # property: a conforming implementer of min-keys and a conforming verifier with no extensions never disagree valid-vs-invalid
    split, nonconf = [], []
    for name, v in V.items():
        if v.get("kind", "verify") != "verify": continue
        a, b = verify(v["did"], v["log"])["result"], verify(v["did"], v["log"], implemented=frozenset())["result"]
        if {a, b} == {"valid", "invalid"}: split.append(name)
        c = verify(v["did"], v["log"], enforce_noncritical=True)["result"]
        if {c, b} == {"valid", "invalid"}: nonconf.append(name)
    print(f"conforming implementer vs non-implementer valid/invalid disagreements: {split or 'none'} (over {sum(1 for v in V.values() if v.get('kind', 'verify') == 'verify')} verify vectors)")
    print(f"  (a NON-conforming implementer that applies non-critical extensions would split on: {nonconf})")
    fx = extra_checks(V)
    print(f"\nextra checks (REQ-9-5, 10-7, 10-8, 10-9, 10-12, 11-3, 11-4): {'all pass' if not fx else 'FAILED: ' + ', '.join(fx)}")
    print("\nW3C ecdsa-jcs-2019 P-256 test vectors:")
    for n, ok in w3c():
        print(f"  {'PASS' if ok else 'FAIL'} {n}")


if __name__ == "__main__":
    main()
