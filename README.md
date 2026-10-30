# Hybrid ECDH + ML-KEM Key Establishment (Seminar Project)

A Hybrid Post-quantum Cryptographic Approach To Mitigate Harvest-now, Decrypt-later Attacks.

Prototype with three key-establishment modes (classical ECDH P-256, ML-KEM-768 only, hybrid), a HKDF-SHA256 key combiner, and AES-256-GCM data protection.

## Files
- `hybrid_kex.py`  core protocol and AES-GCM helpers
- `run_tests.py`   10 functional and security test cases (writes `test_results.json`)
- `benchmark.py`   time, message sizes, memory (writes `benchmark_results.json`)

## Run
```
pip install cryptography    # needs a version that includes ML-KEM (50.x was used)
python run_tests.py
python benchmark.py
```

Tested with Python 3.13 and cryptography 50.0.1 (OpenSSL 4.0.2).
