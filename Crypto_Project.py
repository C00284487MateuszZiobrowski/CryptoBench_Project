#Student name:Mateusz Ziobrowski
#Student number:C00284487
#project spec:Crypto Bench

import os
import time
import csv
from pathlib import Path
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Settings

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

PLAINTEXT_SIZE = 10 * 1024
RUNS_PER_POINT = 10

RSA_KEY_SIZES = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: 7680,
    256: 15360,
}

DSA_KEY_SIZES = {
    80: 1024,
    112: 2048,
    128: 3072,
}

ECC_CURVES = {
    80: ec.SECP192R1(),
    112: ec.SECP224R1(),
    128: ec.SECP256R1(),
    192: ec.SECP384R1(),
    256: ec.SECP521R1(),
}

# Helpers

def benchmark(fn, runs=RUNS_PER_POINT):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        end = time.perf_counter()
        times.append((end - start) * 1000)
    return sum(times[1:]) / (len(times) - 1)


def write_csv(path, header, rows):
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def rsa_chunk_size(key_bits):
    k = key_bits // 8
    return k - 2 * 32 - 2


def rsa_encrypt_chunks(pub, msg, key_bits):
    csize = rsa_chunk_size(key_bits)
    chunks = [msg[i:i + csize] for i in range(0, len(msg), csize)]
    out = []
    for c in chunks:
        out.append(pub.encrypt(
            c,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return out


def rsa_decrypt_chunks(priv, chunks):
    pts = []
    for ct in chunks:
        pts.append(priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return b"".join(pts)


def make_line_plot(csv_path, title, xl, yl, xf, yf, af, out_png):
    if not csv_path.exists():
        return

    with csv_path.open("r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        return

    series = {}
    for row in rows:
        algo = row[af]
        x = float(row[xf])
        y = float(row[yf])
        series.setdefault(algo, []).append((x, y))

    for algo in series:
        series[algo].sort()

    plt.figure()
    for algo, pts in series.items():
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        plt.plot(xs, ys, marker="o", label=algo)

    plt.title(title)
    plt.xlabel(xl)
    plt.ylabel(yl)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

# Bench: Keygen

def bench_key_generation():
    rows = []

    for sec, size in RSA_KEY_SIZES.items():
        avg = benchmark(lambda: rsa.generate_private_key(65537, size))
        rows.append(["RSA", sec, size, avg])

    for sec, size in DSA_KEY_SIZES.items():
        avg = benchmark(lambda: dsa.generate_private_key(size))
        rows.append(["DSA", sec, size, avg])

    for sec, curve in ECC_CURVES.items():
        avg = benchmark(lambda: ec.generate_private_key(curve))
        rows.append(["ECC", sec, curve.name, avg])

    out = RESULTS_DIR / "keygen.csv"
    write_csv(out, ["algorithm", "security_bits", "key_param", "avg_time_ms"], rows)

    make_line_plot(
        out, "Key Gen Time", "Security bits", "ms",
        "security_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "keygen.png"
    )

# Bench: Symmetric Encryption

def bench_symmetric_encryption():
    rows = []
    pt = os.urandom(PLAINTEXT_SIZE)

    for bits in (128, 192, 256):
        key = os.urandom(bits // 8)
        nonce = os.urandom(16)

        def enc():
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            e = cipher.encryptor()
            e.update(pt) + e.finalize()

        avg = benchmark(enc)
        rows.append(["AES", bits, "CTR", avg])

    key = os.urandom(32)
    nonce = os.urandom(16)

    def enc_chacha():
        cipher = Cipher(algorithms.ChaCha20(key, nonce), None)
        cipher.encryptor().update(pt)

    avg = benchmark(enc_chacha)
    rows.append(["ChaCha20", 256, "stream", avg])

    out = RESULTS_DIR / "symmetric_encryption.csv"
    write_csv(out, ["algorithm", "key_bits", "mode", "avg_time_ms"], rows)

    make_line_plot(
        out, "Symmetric Enc (10KiB)", "Key bits", "ms",
        "key_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "symmetric_encryption.png"
    )

# Bench: Symmetric Decryption

def bench_symmetric_decryption():
    rows = []
    pt = os.urandom(PLAINTEXT_SIZE)

    for bits in (128, 192, 256):
        key = os.urandom(bits // 8)
        nonce = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        ct = cipher.encryptor().update(pt) + cipher.encryptor().finalize()

        def dec():
            cipher2 = Cipher(algorithms.AES(key), modes.CTR(nonce))
            d = cipher2.decryptor()
            d.update(ct) + d.finalize()

        avg = benchmark(dec)
        rows.append(["AES", bits, "CTR", avg])

    key = os.urandom(32)
    nonce = os.urandom(16)
    ct = Cipher(algorithms.ChaCha20(key, nonce), None).encryptor().update(pt)

    def dec_chacha():
        Cipher(algorithms.ChaCha20(key, nonce), None).decryptor().update(ct)

    avg = benchmark(dec_chacha)
    rows.append(["ChaCha20", 256, "stream", avg])

    out = RESULTS_DIR / "symmetric_decryption.csv"
    write_csv(out, ["algorithm", "key_bits", "mode", "avg_time_ms"], rows)

    make_line_plot(
        out, "Symmetric Dec (10KiB)", "Key bits", "ms",
        "key_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "symmetric_decryption.png"
    )

# Bench: RSA Encryption

def bench_asymmetric_encryption():
    rows = []
    pt = os.urandom(PLAINTEXT_SIZE)

    for sec, size in RSA_KEY_SIZES.items():
        priv = rsa.generate_private_key(65537, size)
        pub = priv.public_key()

        def enc():
            rsa_encrypt_chunks(pub, pt, size)

        avg = benchmark(enc)
        rows.append(["RSA", sec, size, avg])

    out = RESULTS_DIR / "asymmetric_encryption.csv"
    write_csv(out, ["algorithm", "security_bits", "key_size_bits", "avg_time_ms"], rows)

    make_line_plot(
        out, "RSA Enc (10KiB)", "Security bits", "ms",
        "security_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "asymmetric_encryption.png"
    )

# Bench: RSA Decryption

def bench_asymmetric_decryption():
    rows = []
    pt = os.urandom(PLAINTEXT_SIZE)

    for sec, size in RSA_KEY_SIZES.items():
        priv = rsa.generate_private_key(65537, size)
        pub = priv.public_key()
        chunks = rsa_encrypt_chunks(pub, pt, size)

        def dec():
            rsa_decrypt_chunks(priv, chunks)

        avg = benchmark(dec)
        rows.append(["RSA", sec, size, avg])

    out = RESULTS_DIR / "asymmetric_decryption.csv"
    write_csv(out, ["algorithm", "security_bits", "key_size_bits", "avg_time_ms"], rows)

    make_line_plot(
        out, "RSA Dec (10KiB)", "Security bits", "ms",
        "security_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "asymmetric_decryption.png"
    )

# Bench: Signing

def bench_signing():
    rows = []
    msg = os.urandom(PLAINTEXT_SIZE)
    d = hashes.Hash(hashes.SHA256())
    d.update(msg)
    digest = d.finalize()

    for sec, size in RSA_KEY_SIZES.items():
        priv = rsa.generate_private_key(65537, size)

        def sign():
            priv.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        avg = benchmark(sign)
        rows.append(["RSA", sec, size, "SHA256", avg])

    for sec, size in DSA_KEY_SIZES.items():
        priv = dsa.generate_private_key(size)

        def sign():
            priv.sign(digest, hashes.SHA256())

        avg = benchmark(sign)
        rows.append(["DSA", sec, size, "SHA256", avg])

    for sec, curve in ECC_CURVES.items():
        priv = ec.generate_private_key(curve)

        def sign():
            priv.sign(digest, ec.ECDSA(hashes.SHA256()))

        avg = benchmark(sign)
        rows.append(["ECC", sec, curve.name, "SHA256", avg])

    out = RESULTS_DIR / "signing.csv"
    write_csv(out, ["algorithm", "security_bits", "key_param", "hash", "avg_time_ms"], rows)

    make_line_plot(
        out, "Signing Time", "Security bits", "ms",
        "security_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "signing.png"
    )

# Bench: Verification

def bench_verification():
    rows = []
    msg = os.urandom(PLAINTEXT_SIZE)
    d = hashes.Hash(hashes.SHA256())
    d.update(msg)
    digest = d.finalize()

    for sec, size in RSA_KEY_SIZES.items():
        priv = rsa.generate_private_key(65537, size)
        pub = priv.public_key()
        sig = priv.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        def verify():
            pub.verify(
                sig,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        avg = benchmark(verify)
        rows.append(["RSA", sec, size, "SHA256", avg])

    for sec, size in DSA_KEY_SIZES.items():
        priv = dsa.generate_private_key(size)
        pub = priv.public_key()
        sig = priv.sign(digest, hashes.SHA256())

        def verify():
            pub.verify(sig, digest, hashes.SHA256())

        avg = benchmark(verify)
        rows.append(["DSA", sec, size, "SHA256", avg])

    for sec, curve in ECC_CURVES.items():
        priv = ec.generate_private_key(curve)
        pub = priv.public_key()
        sig = priv.sign(digest, ec.ECDSA(hashes.SHA256()))

        def verify():
            pub.verify(sig, digest, ec.ECDSA(hashes.SHA256()))

        avg = benchmark(verify)
        rows.append(["ECC", sec, curve.name, "SHA256", avg])

    out = RESULTS_DIR / "verification.csv"
    write_csv(out, ["algorithm", "security_bits", "key_param", "hash", "avg_time_ms"], rows)

    make_line_plot(
        out, "Verification Time", "Security bits", "ms",
        "security_bits", "avg_time_ms", "algorithm",
        RESULTS_DIR / "verification.png"
    )

# Main

def main():
    print("[*] Benchmarking key generation...")
    bench_key_generation()

    print("[*] Symmetric enc...")
    bench_symmetric_encryption()

    print("[*] Symmetric dec...")
    bench_symmetric_decryption()

    print("[*] RSA enc...")
    bench_asymmetric_encryption()

    print("[*] RSA dec...")
    bench_asymmetric_decryption()

    print("[*] Signing...")
    bench_signing()

    print("[*] Verification...")
    bench_verification()

    print("[*] Done. Check 'results' folder.")

if __name__ == "__main__":
    main()

