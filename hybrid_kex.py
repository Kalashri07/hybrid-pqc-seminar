"""Hybrid ECDH (P-256) + ML-KEM-768 key establishment with AES-256-GCM.

Three modes are implemented so they can be compared:
  classical : ECDH P-256 only
  pqc       : ML-KEM-768 only
  hybrid    : ECDH P-256 + ML-KEM-768, secrets combined with HKDF-SHA256
"""
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM = mlkem.MLKEM768PrivateKey
KEM_PUB = mlkem.MLKEM768PublicKey
CURVE = ec.SECP256R1()
INFO = b"hybrid-ecdh-p256-mlkem768-v1"
RAW = dict(encoding=serialization.Encoding.X962,
           format=serialization.PublicFormat.UncompressedPoint)


@dataclass
class Handshake:
    """Bytes that cross the network and the derived 32-byte session key."""
    client_msg: bytes     # client -> server
    server_msg: bytes     # server -> client
    client_key: bytes
    server_key: bytes

    @property
    def overhead(self):
        return len(self.client_msg) + len(self.server_msg)


def derive(secrets, transcript):
    """HKDF-SHA256 over the concatenated shared secrets, bound to the transcript."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=INFO + transcript).derive(b"".join(secrets))


# ---------- classical ECDH ----------
def ecdh_client_start():
    sk = ec.generate_private_key(CURVE)
    return sk, sk.public_key().public_bytes(**RAW)


def ecdh_server_respond(client_pub):
    sk = ec.generate_private_key(CURVE)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, client_pub)
    return sk.exchange(ec.ECDH(), peer), sk.public_key().public_bytes(**RAW)


def ecdh_client_finish(sk, server_pub):
    peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, server_pub)
    return sk.exchange(ec.ECDH(), peer)


# ---------- ML-KEM ----------
def kem_client_start():
    sk = KEM.generate()
    return sk, sk.public_key().public_bytes_raw()


def kem_server_respond(client_pub):
    ss, ct = KEM_PUB.from_public_bytes(client_pub).encapsulate()
    return ss, ct


def kem_client_finish(sk, ct):
    return sk.decapsulate(ct)


# ---------- full handshakes ----------
def handshake(mode):
    if mode == "classical":
        sk, cpub = ecdh_client_start()
        ss_s, spub = ecdh_server_respond(cpub)
        ss_c = ecdh_client_finish(sk, spub)
        t = cpub + spub
        return Handshake(cpub, spub, derive([ss_c], t), derive([ss_s], t))
    if mode == "pqc":
        sk, cpub = kem_client_start()
        ss_s, ct = kem_server_respond(cpub)
        ss_c = kem_client_finish(sk, ct)
        t = cpub + ct
        return Handshake(cpub, ct, derive([ss_c], t), derive([ss_s], t))
    if mode == "hybrid":
        e_sk, e_pub = ecdh_client_start()
        k_sk, k_pub = kem_client_start()
        client_msg = e_pub + k_pub
        e_ss_s, e_spub = ecdh_server_respond(e_pub)
        k_ss_s, k_ct = kem_server_respond(k_pub)
        server_msg = e_spub + k_ct
        e_ss_c = ecdh_client_finish(e_sk, e_spub)
        k_ss_c = kem_client_finish(k_sk, k_ct)
        t = client_msg + server_msg
        return Handshake(client_msg, server_msg,
                         derive([e_ss_c, k_ss_c], t), derive([e_ss_s, k_ss_s], t))
    raise ValueError(mode)


# ---------- AES-256-GCM data protection ----------
def encrypt(key, plaintext, aad=b""):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key, blob, aad=b""):
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
