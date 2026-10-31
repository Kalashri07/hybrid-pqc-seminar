"""Step-by-step live demo of the hybrid ECDH + ML-KEM handshake.
Run:  python demo.py
Press Enter between steps (use  python demo.py --auto  to run without pausing).
"""
import sys

from cryptography.exceptions import InvalidTag

import hybrid_kex as hk

AUTO = "--auto" in sys.argv


def pause():
    if not AUTO:
        input("\n   [press Enter to continue]")


def step(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def hx(b, n=16):
    return b[:n].hex() + ("..." if len(b) > n else "")


step("STEP 1 - CLIENT creates two key pairs (classical + post-quantum)")
e_sk, e_pub = hk.ecdh_client_start()
k_sk, k_pub = hk.kem_client_start()
print(f"   ECDH P-256 public key : {len(e_pub):>5} bytes  {hx(e_pub)}")
print(f"   ML-KEM-768 public key : {len(k_pub):>5} bytes  {hx(k_pub)}")
print(f"   Message M1 sent to server = {len(e_pub) + len(k_pub)} bytes")
print("   (An attacker on the network can see and record M1.)")
pause()

step("STEP 2 - SERVER responds with its own ECDH key and an ML-KEM ciphertext")
e_ss_s, e_spub = hk.ecdh_server_respond(e_pub)
k_ss_s, k_ct = hk.kem_server_respond(k_pub)
print(f"   ECDH P-256 public key : {len(e_spub):>5} bytes  {hx(e_spub)}")
print(f"   ML-KEM ciphertext     : {len(k_ct):>5} bytes  {hx(k_ct)}")
print(f"   Message M2 sent to client = {len(e_spub) + len(k_ct)} bytes")
print(f"   Server's ECDH secret  : {hx(e_ss_s)}")
print(f"   Server's ML-KEM secret: {hx(k_ss_s)}")
pause()

step("STEP 3 - CLIENT recovers both secrets")
e_ss_c = hk.ecdh_client_finish(e_sk, e_spub)
k_ss_c = hk.kem_client_finish(k_sk, k_ct)
print(f"   Client's ECDH secret  : {hx(e_ss_c)}   match server: {e_ss_c == e_ss_s}")
print(f"   Client's ML-KEM secret: {hx(k_ss_c)}   match server: {k_ss_c == k_ss_s}")
pause()

step("STEP 4 - BOTH SIDES combine the secrets with HKDF-SHA256")
t = e_pub + k_pub + e_spub + k_ct
key_c = hk.derive([e_ss_c, k_ss_c], t)
key_s = hk.derive([e_ss_s, k_ss_s], t)
print(f"   Client session key: {key_c.hex()}")
print(f"   Server session key: {key_s.hex()}")
print(f"   Keys identical    : {key_c == key_s}   (32 bytes = 256 bits)")
pause()

step("STEP 5 - Encrypt and decrypt a message with AES-256-GCM")
msg = b"Confidential record that must stay secret for 20 years."
blob = hk.encrypt(key_c, msg)
print(f"   Plaintext : {msg.decode()}")
print(f"   Ciphertext: {hx(blob, 24)}  ({len(blob)} bytes incl. nonce and tag)")
print(f"   Decrypted by server: {hk.decrypt(key_s, blob).decode()}")
pause()

step("STEP 6 - ATTACK 1: attacker flips one bit of the ciphertext")
bad = bytearray(blob)
bad[-1] ^= 1
try:
    hk.decrypt(key_s, bytes(bad))
    print("   Decrypted (unexpected!)")
except InvalidTag:
    print("   RESULT: decryption REJECTED (InvalidTag) - tampering detected.")
pause()

step("STEP 7 - ATTACK 2: quantum computer breaks ECDH (attacker knows ECDH secret)")
guess = hk.derive([e_ss_s, b"\x00" * 32], t)
print(f"   Attacker's guessed key: {guess.hex()[:32]}...")
print(f"   Real session key      : {key_s.hex()[:32]}...")
print(f"   Attacker got the key  : {guess == key_s}")
print("   RESULT: ECDH alone is not enough - the ML-KEM secret is still needed.")
pause()

step("STEP 8 - Compare the three modes (communication cost per handshake)")
for m in ("classical", "pqc", "hybrid"):
    h = hk.handshake(m)
    print(f"   {m:<10} total bytes exchanged: {h.overhead:>5}   keys match: {h.client_key == h.server_key}")
print("\nDemo finished.")
