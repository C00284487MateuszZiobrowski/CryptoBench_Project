import time
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives import hashes

# Security levels and key sizes
security_to_key_bits = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: 7680,
    256: 15360
}

# Benchmarks keypair generation
def benchmark_key_generation():
    rsa_results, dsa_results, ecc_results = [], [], []
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]
    dsa_sizes = [1024, 2048, 3072]
    ecc_curves = [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]

    for rsa_size in rsa_sizes:
        start_time = time.time()
        rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
        end_time = time.time()
        rsa_results.append((rsa_size, end_time - start_time))

    for dsa_size in dsa_sizes:
        start_time = time.time()
        dsa.generate_private_key(key_size=dsa_size)
        end_time = time.time()
        dsa_results.append((dsa_size, end_time - start_time))

    for curve in ecc_curves:
        start_time = time.time()
        ec.generate_private_key(curve)
        end_time = time.time()
        ecc_results.append((curve.name, end_time - start_time))

    return rsa_results, dsa_results, ecc_results

# Benchmarks RSA encryption
def benchmark_rsa_encryption():
    results = []
    plaintext = b"Test message for RSA encryption"
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]

    for rsa_size in rsa_sizes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
        public_key = key.public_key()
        start_time = time.time()
        public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end_time = time.time()
        results.append((rsa_size, end_time - start_time))

    return results

# Benchmarks RSA decryption
def benchmark_rsa_decryption():
    results = []
    plaintext = b"Test message for RSA decryption"
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]

    for rsa_size in rsa_sizes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
        public_key = key.public_key()
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        start_time = time.time()
        key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end_time = time.time()
        results.append((rsa_size, end_time - start_time))

    return results

# Benchmarks digital signing
def benchmark_digital_signing():
    rsa_results, dsa_results, ecc_results = [], [], []
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]
    dsa_sizes = [1024, 2048, 3072]
    ecc_curves = [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
    message = b"Signing test message"

    for rsa_size in rsa_sizes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
        start_time = time.time()
        key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end_time = time.time()
        rsa_results.append((rsa_size, end_time - start_time))

    for dsa_size in dsa_sizes:
        key = dsa.generate_private_key(key_size=dsa_size)
        start_time = time.time()
        key.sign(message, hashes.SHA256())
        end_time = time.time()
        dsa_results.append((dsa_size, end_time - start_time))

    for curve in ecc_curves:
        key = ec.generate_private_key(curve)
        start_time = time.time()
        key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_time = time.time()
        ecc_results.append((curve.name, end_time - start_time))

    return rsa_results, dsa_results, ecc_results

# Function to benchmark signature verification
def benchmark_signature_verification():
    results = []
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]
    message = b"Verification test message"

    for rsa_size in rsa_sizes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
        public_key = key.public_key()
        signature = key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        start_time = time.time()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end_time = time.time()
        results.append((rsa_size, end_time - start_time))

    return results

# Plotting
def plot_results(data, title, x_label, y_label, legend_labels):
    plt.figure(figsize=(10, 6))
    for label, values in zip(legend_labels, data):
        x, y = zip(*values)
        plt.plot(x, y, marker='o', label=label)
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.legend()
    plt.grid()
    plt.show()

# Main code
if __name__ == "__main__":
    rsa_gen, dsa_gen, ecc_gen = benchmark_key_generation()
    plot_results([rsa_gen, dsa_gen, ecc_gen], "Keypair Generation", "Key Size / Curve", "Time (s)", ["RSA", "DSA", "ECC"])

    rsa_enc = benchmark_rsa_encryption()
    plot_results([rsa_enc], "RSA Encryption", "Key Size", "Time (s)", ["RSA"])

    rsa_dec = benchmark_rsa_decryption()
    plot_results([rsa_dec], "RSA Decryption", "Key Size", "Time (s)", ["RSA"])

    rsa_sign, dsa_sign, ecc_sign = benchmark_digital_signing()
    plot_results([rsa_sign, dsa_sign, ecc_sign], "Digital Signing", "Key Size / Curve", "Time (s)", ["RSA", "DSA", "ECC"])

    rsa_verify = benchmark_signature_verification()
    plot_results([rsa_verify], "Signature Verification", "Key Size", "Time (s)", ["RSA"])
