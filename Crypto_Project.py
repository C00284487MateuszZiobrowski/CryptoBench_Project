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

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

PLAINTEXT_SIZE = 10 * 1024  # 10 KiB
RUNS_PER_POINT = 10         # number of runs per data point (first is warm-up)

# Approximate mappings from "security bits" to parameters
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
    80: ec.SECP192R1(),   # roughly 80-96 bits of security
    112: ec.SECP224R1(),
    128: ec.SECP256R1(),
    192: ec.SECP384R1(),
    256: ec.SECP521R1(),
}


def benchmark(fn, runs: int = RUNS_PER_POINT) -> float:
    
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        end = time.perf_counter()
        times.append((end - start) * 1000.0)  
    if len(times) <= 1:
        return times[0] if times else 0.0
    return sum(times[1:]) / (len(times) - 1)


def write_csv(path: Path, header, rows):

    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def rsa_chunk_size(key_size_bits: int) -> int:
 
    k = key_size_bits // 8
    return k - 2 * 32 - 2


def rsa_encrypt_chunks(public_key, message: bytes, key_size_bits: int):
    chunk_size = rsa_chunk_size(key_size_bits)
    chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
    encrypted_chunks = []
    for chunk in chunks:
        ct = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_chunks.append(ct)
    return encrypted_chunks


def rsa_decrypt_chunks(private_key, encrypted_chunks):
    parts = []
    for ct in encrypted_chunks:
        pt = private_key.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        parts.append(pt)
    return b"".join(parts)


def make_line_plot(csv_path: Path, title: str, x_label: str, y_label: str,
                   x_field: str, y_field: str, algo_field: str, output_png: Path):
    
    #Generic function to read a CSV and plot lines:
     #x-axis: x_field
     #y-axis: y_field
     #one line per distinct value in algo_field
    
    if not csv_path.exists():
        print(f"[WARN] CSV file not found for plotting: {csv_path}")
        return

    # Read CSV
    with csv_path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        print(f"[WARN] No data in {csv_path}")
        return

    # Group by algorithm
    series = {}
    for row in rows:
        algo = row[algo_field]
        x_val = float(row[x_field])
        y_val = float(row[y_field])
        series.setdefault(algo, []).append((x_val, y_val))

    # Sort each series by x-value
    for algo in series:
        series[algo].sort(key=lambda pair: pair[0])

    # Plot
    plt.figure()
    for algo, points in series.items():
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        plt.plot(xs, ys, marker="o", label=algo)

    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_png)
    plt.close()
    print(f"[INFO] Saved plot: {output_png}")



#Key Pair Generation – RSA, DSA, ECC

def bench_key_generation():
  
    rows = []

    # RSA
    for sec_bits, key_size in RSA_KEY_SIZES.items():
        avg_ms = benchmark(
            lambda: rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
        )
        rows.append(["RSA", sec_bits, key_size, avg_ms])

    # DSA
    for sec_bits, key_size in DSA_KEY_SIZES.items():
        avg_ms = benchmark(
            lambda: dsa.generate_private_key(
                key_size=key_size
            )
        )
        rows.append(["DSA", sec_bits, key_size, avg_ms])

    # ECC
    for sec_bits, curve in ECC_CURVES.items():
        avg_ms = benchmark(
            lambda: ec.generate_private_key(curve)
        )
        rows.append(["ECC", sec_bits, curve.name, avg_ms])

    out_csv = RESULTS_DIR / "keygen.csv"
    write_csv(
        out_csv,
        header=["algorithm", "security_bits", "key_param", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="Key Pair Generation Time",
        x_label="Security level (bits)",
        y_label="Average time (ms)",
        x_field="security_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "keygen.png",
    )



# Symmetric Encryption & Decryption – AES, ChaCha20


def bench_symmetric_encryption():
    """
    Benchmarks AES (128/192/256-bit) and ChaCha20 encryption of a 10KiB message.
    Results saved to results/symmetric_encryption.csv
    """
    rows = []
    plaintext = os.urandom(PLAINTEXT_SIZE)

    # AES-CTR with different key sizes
    for key_bits in (128, 192, 256):
        key = os.urandom(key_bits // 8)
        nonce = os.urandom(16)  # 128-bit nonce for CTR

        def encrypt_aes():
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            _ = encryptor.update(plaintext) + encryptor.finalize()

        avg_ms = benchmark(encrypt_aes)
        rows.append(["AES", key_bits, "CTR", avg_ms])

    # ChaCha20 – 256-bit key
    key = os.urandom(32)
    nonce = os.urandom(16)

    def encrypt_chacha():
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        _ = encryptor.update(plaintext)

    avg_ms = benchmark(encrypt_chacha)
    rows.append(["ChaCha20", 256, "stream", avg_ms])

    out_csv = RESULTS_DIR / "symmetric_encryption.csv"
    write_csv(
        out_csv,
        header=["algorithm", "key_bits", "mode", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="Symmetric Encryption Time (10KiB)",
        x_label="Key size (bits)",
        y_label="Average time (ms)",
        x_field="key_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "symmetric_encryption.png",
    )


def bench_symmetric_decryption():
    """
    Benchmarks AES (128/192/256-bit) and ChaCha20 decryption of a 10KiB message.
    We first encrypt once (outside timing), then repeatedly decrypt.
    Results saved to results/symmetric_decryption.csv
    """
    rows = []
    plaintext = os.urandom(PLAINTEXT_SIZE)

    # AES-CTR
    for key_bits in (128, 192, 256):
        key = os.urandom(key_bits // 8)
        nonce = os.urandom(16)

   
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        def decrypt_aes():
            cipher_dec = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher_dec.decryptor()
            _ = decryptor.update(ciphertext) + decryptor.finalize()

        avg_ms = benchmark(decrypt_aes)
        rows.append(["AES", key_bits, "CTR", avg_ms])

    # ChaCha20
    key = os.urandom(32)
    nonce = os.urandom(16)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    def decrypt_chacha():
        cipher_dec = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher_dec.decryptor()
        _ = decryptor.update(ciphertext)

    avg_ms = benchmark(decrypt_chacha)
    rows.append(["ChaCha20", 256, "stream", avg_ms])

    out_csv = RESULTS_DIR / "symmetric_decryption.csv"
    write_csv(
        out_csv,
        header=["algorithm", "key_bits", "mode", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="Symmetric Decryption Time (10KiB)",
        x_label="Key size (bits)",
        y_label="Average time (ms)",
        x_field="key_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "symmetric_decryption.png",
    )



# Asymmetric Encryption & Decryption – RSA (chunked, 10KiB)


def bench_asymmetric_encryption():

    rows = []
    plaintext = os.urandom(PLAINTEXT_SIZE)

    for sec_bits, key_size in RSA_KEY_SIZES.items():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

        def encrypt_rsa():
            _ = rsa_encrypt_chunks(public_key, plaintext, key_size)

        avg_ms = benchmark(encrypt_rsa)
        rows.append(["RSA", sec_bits, key_size, avg_ms])

    out_csv = RESULTS_DIR / "asymmetric_encryption.csv"
    write_csv(
        out_csv,
        header=["algorithm", "security_bits", "key_size_bits", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="RSA Asymmetric Encryption Time (10KiB)",
        x_label="Security level (bits)",
        y_label="Average time (ms)",
        x_field="security_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "asymmetric_encryption.png",
    )


def bench_asymmetric_decryption():

    rows = []
    plaintext = os.urandom(PLAINTEXT_SIZE)

    for sec_bits, key_size in RSA_KEY_SIZES.items():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

       
        encrypted_chunks = rsa_encrypt_chunks(public_key, plaintext, key_size)

        def decrypt_rsa():
            _ = rsa_decrypt_chunks(private_key, encrypted_chunks)

        avg_ms = benchmark(decrypt_rsa)
        rows.append(["RSA", sec_bits, key_size, avg_ms])

    out_csv = RESULTS_DIR / "asymmetric_decryption.csv"
    write_csv(
        out_csv,
        header=["algorithm", "security_bits", "key_size_bits", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="RSA Asymmetric Decryption Time (10KiB)",
        x_label="Security level (bits)",
        y_label="Average time (ms)",
        x_field="security_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "asymmetric_decryption.png",
    )


# -----------------------------------------------------------------------------
# 4. Digital Signing – RSA, DSA, ECC
# -----------------------------------------------------------------------------

def bench_signing():
    
    #Benchmarks digital signing of a 10KiB message (signing its SHA-256 hash):
    - #RSA for all security levels
    - #DSA where key sizes are supported
    - #ECC for the chosen curves

    Results saved to results/signing.csv
    
    rows = []
    message = os.urandom(PLAINTEXT_SIZE)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    digest = hasher.finalize()

    # RSA signing – PSS with SHA-256
    for sec_bits, key_size in RSA_KEY_SIZES.items():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        def sign_rsa():
            _ = private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        avg_ms = benchmark(sign_rsa)
        rows.append(["RSA", sec_bits, key_size, "SHA256", avg_ms])

    # DSA signing – SHA-256
    for sec_bits, key_size in DSA_KEY_SIZES.items():
        private_key = dsa.generate_private_key(
            key_size=key_size
        )

        def sign_dsa():
            _ = private_key.sign(
                digest,
                hashes.SHA256()
            )

        avg_ms = benchmark(sign_dsa)
        rows.append(["DSA", sec_bits, key_size, "SHA256", avg_ms])

    # ECC signing – ECDSA with SHA-256
    for sec_bits, curve in ECC_CURVES.items():
        private_key = ec.generate_private_key(curve)

        def sign_ecc():
            _ = private_key.sign(
                digest,
                ec.ECDSA(hashes.SHA256())
            )

        avg_ms = benchmark(sign_ecc)
        rows.append(["ECC", sec_bits, curve.name, "SHA256", avg_ms])

    out_csv = RESULTS_DIR / "signing.csv"
    write_csv(
        out_csv,
        header=["algorithm", "security_bits", "key_param", "hash", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="Digital Signing Time (10KiB hash)",
        x_label="Security level (bits)",
        y_label="Average time (ms)",
        x_field="security_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "signing.png",
    )



# Signature Verification – RSA, DSA, ECC


def bench_verification():
   
    rows = []
    message = os.urandom(PLAINTEXT_SIZE)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    digest = hasher.finalize()

    # RSA verification
    for sec_bits, key_size in RSA_KEY_SIZES.items():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        def verify_rsa():
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        avg_ms = benchmark(verify_rsa)
        rows.append(["RSA", sec_bits, key_size, "SHA256", avg_ms])

    # DSA verification
    for sec_bits, key_size in DSA_KEY_SIZES.items():
        private_key = dsa.generate_private_key(
            key_size=key_size
        )
        public_key = private_key.public_key()
        signature = private_key.sign(digest, hashes.SHA256())

        def verify_dsa():
            public_key.verify(
                signature,
                digest,
                hashes.SHA256()
            )

        avg_ms = benchmark(verify_dsa)
        rows.append(["DSA", sec_bits, key_size, "SHA256", avg_ms])

    # ECC verification
    for sec_bits, curve in ECC_CURVES.items():
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        signature = private_key.sign(
            digest,
            ec.ECDSA(hashes.SHA256())
        )

        def verify_ecc():
            public_key.verify(
                signature,
                digest,
                ec.ECDSA(hashes.SHA256())
            )

        avg_ms = benchmark(verify_ecc)
        rows.append(["ECC", sec_bits, curve.name, "SHA256", avg_ms])

    out_csv = RESULTS_DIR / "verification.csv"
    write_csv(
        out_csv,
        header=["algorithm", "security_bits", "key_param", "hash", "avg_time_ms"],
        rows=rows,
    )
    make_line_plot(
        csv_path=out_csv,
        title="Signature Verification Time (10KiB hash)",
        x_label="Security level (bits)",
        y_label="Average time (ms)",
        x_field="security_bits",
        y_field="avg_time_ms",
        algo_field="algorithm",
        output_png=RESULTS_DIR / "verification.png",
    )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    print("[*] Benchmarking key generation...")
    bench_key_generation()

    print("[*] Benchmarking symmetric encryption...")
    bench_symmetric_encryption()

    print("[*] Benchmarking symmetric decryption...")
    bench_symmetric_decryption()

    print("[*] Benchmarking asymmetric (RSA) encryption...")
    bench_asymmetric_encryption()

    print("[*] Benchmarking asymmetric (RSA) decryption...")
    bench_asymmetric_decryption()

    print("[*] Benchmarking digital signing (RSA, DSA, ECC)...")
    bench_signing()

    print("[*] Benchmarking signature verification (RSA, DSA, ECC)...")
    bench_verification()

    print("[*] Done. Check the 'results' directory for CSVs and plots.")


if __name__ == "__main__":
    main()
