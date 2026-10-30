"""Functional / security test cases for the hybrid key-establishment prototype."""
import json
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

import hybrid_kex as hk

results = []


def case(tid, action, expected, fn):
    try:
        actual, ok = fn()
    except Exception as e:  # unexpected crash counts as a failure
        actual, ok = f"exception: {type(e).__name__}", False
    results.append(dict(id=tid, action=action, expected=expected,
                        actual=actual, status="Pass" if ok else "Fail"))
    print(f"{tid} [{'PASS' if ok else 'FAIL'}] {action}\n      -> {actual}")


MSG = b"Confidential record that must stay secret for 20 years."


def tc01():
    h = hk.handshake("hybrid")
    return (f"keys equal, len={len(h.client_key)} B", h.client_key == h.server_key
            and len(h.client_key) == 32)


def tc02():
    h = hk.handshake("hybrid")
    pt = hk.decrypt(h.server_key, hk.encrypt(h.client_key, MSG))
    return ("plaintext recovered" if pt == MSG else "mismatch", pt == MSG)


def tc03():
    keys = {hk.handshake("hybrid").client_key for _ in range(200)}
    return (f"{len(keys)} unique keys in 200 sessions", len(keys) == 200)


def tc04():
    h = hk.handshake("classical")
    h2 = hk.handshake("pqc")
    return ("classical and PQC modes both agree",
            h.client_key == h.server_key and h2.client_key == h2.server_key)


def tc05():
    # Tamper with the ML-KEM ciphertext: decapsulation implicitly rejects ->
    # client derives a different key and AES-GCM authentication fails.
    e_sk, e_pub = hk.ecdh_client_start()
    k_sk, k_pub = hk.kem_client_start()
    e_ss_s, e_spub = hk.ecdh_server_respond(e_pub)
    k_ss_s, ct = hk.kem_server_respond(k_pub)
    bad = bytearray(ct)
    bad[10] ^= 0x01
    k_ss_c = hk.kem_client_finish(k_sk, bytes(bad))
    e_ss_c = hk.ecdh_client_finish(e_sk, e_spub)
    t = e_pub + k_pub + e_spub + ct
    key_c = hk.derive([e_ss_c, k_ss_c], t)
    key_s = hk.derive([e_ss_s, k_ss_s], t)
    try:
        hk.decrypt(key_c, hk.encrypt(key_s, MSG))
        return ("decrypted (unexpected)", False)
    except InvalidTag:
        return ("keys differ; AES-GCM rejects (InvalidTag)", key_c != key_s)


def tc06():
    e_sk, e_pub = hk.ecdh_client_start()
    k_sk, k_pub = hk.kem_client_start()
    e_ss_s, e_spub = hk.ecdh_server_respond(e_pub)
    k_ss_s, ct = hk.kem_server_respond(k_pub)
    other = hk.ecdh_client_start()[1]       # attacker swaps the server ECDH key
    e_ss_c = hk.ecdh_client_finish(e_sk, other)
    k_ss_c = hk.kem_client_finish(k_sk, ct)
    key_c = hk.derive([e_ss_c, k_ss_c], b"x")
    key_s = hk.derive([e_ss_s, k_ss_s], b"x")
    return ("keys differ after ECDH key substitution", key_c != key_s)


def tc07():
    h = hk.handshake("hybrid")
    blob = bytearray(hk.encrypt(h.client_key, MSG))
    blob[-1] ^= 0x01
    try:
        hk.decrypt(h.server_key, bytes(blob))
        return ("decrypted (unexpected)", False)
    except InvalidTag:
        return ("InvalidTag raised", True)


def tc08():
    # Simulate a quantum break of ECDH: attacker knows the ECDH secret exactly
    # but has no ML-KEM secret, so a key derived from ECDH alone must not match.
    e_sk, e_pub = hk.ecdh_client_start()
    k_sk, k_pub = hk.kem_client_start()
    e_ss_s, e_spub = hk.ecdh_server_respond(e_pub)
    k_ss_s, ct = hk.kem_server_respond(k_pub)
    t = e_pub + k_pub + e_spub + ct
    true_key = hk.derive([e_ss_s, k_ss_s], t)
    guess = hk.derive([e_ss_s, b"\x00" * 32], t)          # ECDH secret known, KEM unknown
    classical_only = hk.derive([e_ss_s], t)
    ok = guess != true_key and classical_only != true_key
    return ("key not recoverable from ECDH secret alone", ok)


def tc09():
    try:
        hk.ecdh_server_respond(b"\x04" + b"\x01" * 64)     # point not on curve
        return ("accepted invalid point (unexpected)", False)
    except ValueError:
        return ("invalid curve point rejected (ValueError)", True)


def tc10():
    h = hk.handshake("hybrid")
    blob = hk.encrypt(h.client_key, MSG, aad=b"session-1")
    try:
        hk.decrypt(h.server_key, blob, aad=b"session-2")
        return ("decrypted (unexpected)", False)
    except InvalidTag:
        return ("AAD mismatch rejected (InvalidTag)", True)


case("TC01", "Run hybrid handshake; compare client and server keys",
     "Both sides derive the same 32-byte key", tc01)
case("TC02", "Encrypt message with client key, decrypt with server key",
     "Original plaintext recovered", tc02)
case("TC03", "Run 200 hybrid sessions and collect keys",
     "All session keys are unique", tc03)
case("TC04", "Run classical-only and PQC-only handshakes",
     "Keys agree in both modes", tc04)
case("TC05", "Flip one bit of the ML-KEM ciphertext in transit",
     "Keys differ; AES-GCM decryption fails", tc05)
case("TC06", "Substitute the server ECDH public key",
     "Keys differ; no shared secret", tc06)
case("TC07", "Flip one bit of the AES-GCM ciphertext",
     "Authentication tag check fails", tc07)
case("TC08", "Attacker knows ECDH secret (broken by quantum), not ML-KEM",
     "Hybrid session key still not recoverable", tc08)
case("TC09", "Send an ECDH point that is not on the curve",
     "Point rejected", tc09)
case("TC10", "Decrypt with different associated data",
     "Authentication fails", tc10)

passed = sum(r["status"] == "Pass" for r in results)
print(f"\n{passed}/{len(results)} tests passed")
json.dump(results, open("test_results.json", "w"), indent=2)
sys.exit(0 if passed == len(results) else 1)
