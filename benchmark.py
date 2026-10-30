"""Benchmark classical, PQC and hybrid handshakes: time, message sizes, memory."""
import json
import statistics
import time
import tracemalloc

import hybrid_kex as hk

N = 1000
out = {}

# warm-up
for m in ("classical", "pqc", "hybrid"):
    for _ in range(50):
        hk.handshake(m)

for m in ("classical", "pqc", "hybrid"):
    times = []
    for _ in range(N):
        t0 = time.perf_counter()
        h = hk.handshake(m)
        times.append((time.perf_counter() - t0) * 1000)
    tracemalloc.start()
    hk.handshake(m)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    out[m] = dict(
        mean_ms=statistics.mean(times),
        median_ms=statistics.median(times),
        stdev_ms=statistics.stdev(times),
        client_bytes=len(h.client_msg),
        server_bytes=len(h.server_msg),
        total_bytes=h.overhead,
        peak_kib=peak / 1024,
    )

# AES-GCM throughput on a 1 MiB payload
h = hk.handshake("hybrid")
data = bytes(1024 * 1024)
t0 = time.perf_counter()
for _ in range(100):
    hk.decrypt(h.server_key, hk.encrypt(h.client_key, data))
dt = time.perf_counter() - t0
out["aes_gcm_mib_per_s"] = 100 / dt

# per-primitive timings for hybrid components
def timeit(fn, n=1000):
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n * 1000

k_sk, k_pub = hk.kem_client_start()
_, ct = hk.kem_server_respond(k_pub)
e_sk, e_pub = hk.ecdh_client_start()
out["primitives_ms"] = {
    "ECDH keygen": timeit(hk.ecdh_client_start),
    "ECDH exchange": timeit(lambda: hk.ecdh_server_respond(e_pub)),
    "ML-KEM keygen": timeit(hk.kem_client_start),
    "ML-KEM encaps": timeit(lambda: hk.kem_server_respond(k_pub)),
    "ML-KEM decaps": timeit(lambda: hk.kem_client_finish(k_sk, ct)),
}

json.dump(out, open("benchmark_results.json", "w"), indent=2)
print(f"Handshakes per mode: {N}")
print(f"{'Mode':<10}{'mean ms':>9}{'median':>9}{'stdev':>8}{'C->S B':>8}{'S->C B':>8}{'total B':>9}{'peak KiB':>10}")
for m in ("classical", "pqc", "hybrid"):
    r = out[m]
    print(f"{m:<10}{r['mean_ms']:>9.3f}{r['median_ms']:>9.3f}{r['stdev_ms']:>8.3f}"
          f"{r['client_bytes']:>8}{r['server_bytes']:>8}{r['total_bytes']:>9}{r['peak_kib']:>10.1f}")
print("\nPer-primitive mean time (ms):")
for k, v in out["primitives_ms"].items():
    print(f"  {k:<14}{v:.4f}")
print(f"\nAES-256-GCM encrypt+decrypt throughput (1 MiB): {out['aes_gcm_mib_per_s']:.0f} MiB/s")
