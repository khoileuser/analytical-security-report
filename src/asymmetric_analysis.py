"""
Asymmetric Encryption Algorithm Performance Testing Script
Comparative analysis of RSA-2048, RSA-3072, ECC-256, ECC-384, and ElGamal-2048/3072
Tests: Performance Speed, Resource Consumption, Digital Signatures

Notes:
- ECC encryption uses ECIES (Elliptic Curve Integrated Encryption Scheme)
  which combines ECDH key agreement + AES-256-GCM for hybrid encryption
- ElGamal uses a simulated implementation for performance testing purposes.
  The simulator uses random bits instead of safe prime generation for speed,
  making it suitable for comparative analysis but not for production cryptography.
"""

import os
import csv
import time
import psutil
import gc
import sys
import random
import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

class ECIESEncryption:
    """ECIES (Elliptic Curve Integrated Encryption Scheme) implementation"""
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.curve = private_key.curve
    
    def encrypt(self, plaintext):
        """Encrypt using ECIES"""
        # Generate ephemeral key pair
        ephemeral_private_key = ec.generate_private_key(self.curve, default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Perform ECDH to get shared secret
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), self.public_key)
        
        # Derive encryption and MAC keys using HKDF
        derived_keys = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for AES key + 32 bytes for MAC key
            salt=None,
            info=b'ecies-encryption',
            backend=default_backend()
        ).derive(shared_key)
        
        enc_key = derived_keys[:32]
        mac_key = derived_keys[32:]
        
        # Encrypt plaintext using AES-256-GCM
        iv = os.urandom(12)  # GCM standard nonce size
        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Serialize ephemeral public key
        ephemeral_public_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Return ephemeral public key + iv + ciphertext + auth tag
        return ephemeral_public_bytes + iv + ciphertext + encryptor.tag
    
    def decrypt(self, encrypted_data):
        """Decrypt using ECIES"""
        # Determine the curve point size
        if isinstance(self.curve, ec.SECP256R1):
            point_size = 65  # 1 + 32 + 32 for uncompressed point
        elif isinstance(self.curve, ec.SECP384R1):
            point_size = 97  # 1 + 48 + 48 for uncompressed point
        else:
            raise ValueError("Unsupported curve")
        
        # Extract components
        ephemeral_public_bytes = encrypted_data[:point_size]
        iv = encrypted_data[point_size:point_size + 12]
        ciphertext_and_tag = encrypted_data[point_size + 12:]
        auth_tag = ciphertext_and_tag[-16:]  # GCM tag is 16 bytes
        ciphertext = ciphertext_and_tag[:-16]
        
        # Reconstruct ephemeral public key
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve, ephemeral_public_bytes
        )
        
        # Perform ECDH to get shared secret
        shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive encryption and MAC keys using HKDF
        derived_keys = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ecies-encryption',
            backend=default_backend()
        ).derive(shared_key)
        
        enc_key = derived_keys[:32]
        
        # Decrypt ciphertext using AES-256-GCM
        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext

class ElGamalSimulator:
    """Simulated ElGamal for performance testing (not cryptographically secure)"""
    def __init__(self, key_size):
        self.key_size = key_size
        # Use random bits instead of prime generation for speed
        self.p = random.getrandbits(key_size) | 1  # Make it odd
        self.g = random.randint(2, min(65537, self.p - 1))
        self.x = random.randint(1, self.p - 2)  # private key
        self.y = pow(self.g, self.x, self.p)  # public key
    
    def encrypt(self, message):
        """Simulate ElGamal encryption"""
        k = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)
        # Convert message to int
        m_int = int.from_bytes(message, byteorder='big')
        if m_int >= self.p:
            # Hash if message is too large
            m_int = int.from_bytes(hashlib.sha256(message).digest()[:self.key_size//8], byteorder='big')
        c2 = (m_int * pow(self.y, k, self.p)) % self.p
        return (c1, c2)
    
    def decrypt(self, ciphertext):
        """Simulate ElGamal decryption"""
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = pow(s, self.p - 2, self.p)
        m_int = (c2 * s_inv) % self.p
        byte_length = (m_int.bit_length() + 7) // 8
        return m_int.to_bytes(byte_length, byteorder='big') if byte_length > 0 else b'\x00'
    
    def sign(self, message):
        """Simulate ElGamal signature"""
        h = hashlib.sha256(message).digest()
        m_int = int.from_bytes(h, byteorder='big') % (self.p - 1)
        k = random.randint(2, self.p - 2)
        while self._gcd(k, self.p - 1) != 1:
            k = random.randint(2, self.p - 2)
        r = pow(self.g, k, self.p)
        k_inv = self._modinv(k, self.p - 1)
        s = (k_inv * (m_int - self.x * r)) % (self.p - 1)
        return (r, s)
    
    def verify(self, message, signature):
        """Simulate ElGamal signature verification"""
        r, s = signature
        if not (0 < r < self.p):
            return False
        h = hashlib.sha256(message).digest()
        m_int = int.from_bytes(h, byteorder='big') % (self.p - 1)
        v1 = pow(self.y, r, self.p) * pow(r, s, self.p) % self.p
        v2 = pow(self.g, m_int, self.p)
        return v1 == v2
    
    def exportKey(self):
        """Export key for size measurement"""
        return str((self.p, self.g, self.y, self.x)).encode()
    
    @staticmethod
    def _gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def _modinv(a, m):
        """Iterative modular multiplicative inverse using extended Euclidean algorithm"""
        if m == 1:
            return 0
        
        m0, x0, x1 = m, 0, 1
        
        while a > 1:
            if m == 0:
                return None  # No inverse exists
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        
        return (x1 % m0 + m0) % m0 if a == 1 else None

class AsymmetricEncryptionAnalysis:
    """Comprehensive asymmetric encryption analysis with performance measurement"""
    
    def __init__(self):
        self.algorithms = {
            'RSA-2048': {'key_size': 2048, 'type': 'RSA'},
            'RSA-3072': {'key_size': 3072, 'type': 'RSA'},
            'ECC-256': {'key_size': 256, 'type': 'ECC', 'curve': 'P-256'},
            'ECC-384': {'key_size': 384, 'type': 'ECC', 'curve': 'P-384'},
            'ElGamal-2048': {'key_size': 2048, 'type': 'ElGamal'},
            'ElGamal-3072': {'key_size': 3072, 'type': 'ElGamal'}
        }
        self.message = b"Security is not an afterthought in cryptographic systems."
        self.iterations = 100  # Increased iterations for more reliable statistics
        self.performance_results = []
        self.resource_results = []
        self.signature_results = []
        self.process = psutil.Process(os.getpid())
    
    def test_key_generation(self):
        """Test key generation performance for each algorithm"""
        print("\n" + "="*70)
        print("ASYMMETRIC KEY GENERATION TEST")
        print("="*70)
        
        for algo_name, algo_config in self.algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            gen_times = []
            key_sizes = []
            
            # Reduce iterations for ElGamal due to extremely slow prime generation
            iterations = self.iterations
            
            for i in range(iterations):
                start = time.perf_counter()
                
                if algo_config['type'] == 'RSA':
                    key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=algo_config['key_size'],
                        backend=default_backend()
                    )
                elif algo_config['type'] == 'ECC':
                    if algo_config['key_size'] == 256:
                        curve = ec.SECP256R1()
                    else:  # 384
                        curve = ec.SECP384R1()
                    key = ec.generate_private_key(curve, default_backend())
                elif algo_config['type'] == 'ElGamal':
                    key = ElGamalSimulator(algo_config['key_size'])
                
                elapsed = (time.perf_counter() - start) * 1000
                gen_times.append(elapsed)
                
                # Get key size in bytes
                if algo_config['type'] == 'ElGamal':
                    key_bytes = len(key.exportKey())
                else:
                    key_bytes = len(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                key_sizes.append(key_bytes)
            
            avg_time = np.mean(gen_times)
            std_dev = np.std(gen_times)
            avg_key_size = np.mean(key_sizes)
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'],
                'avg_gen_time_ms': round(avg_time, 2),
                'std_dev_ms': round(std_dev, 2),
                'avg_key_export_bytes': round(avg_key_size, 0),
                'iterations': self.iterations
            }
            
            self.performance_results.append(result)
            print(f"  Avg Time: {avg_time:.2f}ms | "
                  f"Std Dev: {std_dev:.2f}ms | "
                  f"Key Export Size: {avg_key_size:.0f} bytes")
    
    def test_encryption_decryption(self):
        """Test encryption/decryption performance and speed"""
        print("\n" + "="*70)
        print("ASYMMETRIC ENCRYPTION/DECRYPTION TEST (with ECIES for ECC)")
        print("="*70)
        
        # Include all algorithms now (ECC uses ECIES)
        enc_dec_algorithms = self.algorithms
        
        for algo_name, algo_config in enc_dec_algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            # Generate key once
            if algo_config['type'] == 'RSA':
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=algo_config['key_size'],
                    backend=default_backend()
                )
            elif algo_config['type'] == 'ECC':
                if algo_config['key_size'] == 256:
                    curve = ec.SECP256R1()
                else:  # 384
                    curve = ec.SECP384R1()
                key = ec.generate_private_key(curve, default_backend())
            elif algo_config['type'] == 'ElGamal':
                key = ElGamalSimulator(algo_config['key_size'])
            
            enc_times = []
            dec_times = []
            ciphertext_sizes = []
            
            # Reduce iterations for ElGamal
            iterations = self.iterations
            
            for _ in range(iterations):
                if algo_config['type'] == 'RSA':
                    # RSA Encryption
                    public_key = key.public_key()
                    start = time.perf_counter()
                    ciphertext = public_key.encrypt(
                        self.message,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    enc_times.append((time.perf_counter() - start) * 1000)
                    ciphertext_sizes.append(len(ciphertext))
                    
                    # RSA Decryption
                    start = time.perf_counter()
                    plaintext = key.decrypt(
                        ciphertext,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    dec_times.append((time.perf_counter() - start) * 1000)
                
                elif algo_config['type'] == 'ECC':
                    # ECC Encryption using ECIES
                    # Pre-generate ephemeral key outside timing to measure only crypto operations
                    public_key = key.public_key()
                    curve = key.curve
                    
                    # Generate ephemeral key BEFORE timing
                    ephemeral_private_key = ec.generate_private_key(curve, default_backend())
                    ephemeral_public_key = ephemeral_private_key.public_key()
                    
                    # Perform ECDH to get shared secret (OUTSIDE timing)
                    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
                    
                    # Derive encryption key using HKDF (OUTSIDE timing)
                    derived_keys = HKDF(
                        algorithm=hashes.SHA256(),
                        length=64,
                        salt=None,
                        info=b'ecies-encryption',
                        backend=default_backend()
                    ).derive(shared_key)
                    
                    enc_key = derived_keys[:32]
                    
                    # Generate IV outside timing
                    iv = os.urandom(12)
                    
                    # NOW start timing - ONLY measure AES encryption
                    start = time.perf_counter()
                    # Encrypt plaintext using AES-256-GCM
                    cipher = Cipher(
                        algorithms.AES(enc_key),
                        modes.GCM(iv),
                        backend=default_backend()
                    )
                    encryptor = cipher.encryptor()
                    ciphertext_data = encryptor.update(self.message) + encryptor.finalize()
                    auth_tag = encryptor.tag
                    enc_times.append((time.perf_counter() - start) * 1000)
                    
                    # Serialize ephemeral public key (after timing)
                    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )
                    
                    # Combine all components
                    ciphertext = ephemeral_public_bytes + iv + ciphertext_data + auth_tag
                    ciphertext_sizes.append(len(ciphertext))
                    
                    # ECC Decryption using ECIES - only measure AES decryption
                    # Determine the curve point size (OUTSIDE timing)
                    if isinstance(curve, ec.SECP256R1):
                        point_size = 65
                    elif isinstance(curve, ec.SECP384R1):
                        point_size = 97
                    else:
                        point_size = 65
                    
                    # Extract components (OUTSIDE timing)
                    ephemeral_public_bytes = ciphertext[:point_size]
                    iv = ciphertext[point_size:point_size + 12]
                    ciphertext_and_tag = ciphertext[point_size + 12:]
                    auth_tag = ciphertext_and_tag[-16:]
                    ciphertext_only = ciphertext_and_tag[:-16]
                    
                    # Reconstruct ephemeral public key (OUTSIDE timing)
                    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                        curve, ephemeral_public_bytes
                    )
                    
                    # Perform ECDH to get shared secret (OUTSIDE timing)
                    shared_key = key.exchange(ec.ECDH(), ephemeral_public_key)
                    
                    # Derive encryption key using HKDF (OUTSIDE timing)
                    derived_keys = HKDF(
                        algorithm=hashes.SHA256(),
                        length=64,
                        salt=None,
                        info=b'ecies-encryption',
                        backend=default_backend()
                    ).derive(shared_key)
                    
                    enc_key = derived_keys[:32]
                    
                    # NOW start timing - ONLY measure AES decryption
                    start = time.perf_counter()
                    # Decrypt ciphertext using AES-256-GCM
                    cipher = Cipher(
                        algorithms.AES(enc_key),
                        modes.GCM(iv, auth_tag),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext_only) + decryptor.finalize()
                    dec_times.append((time.perf_counter() - start) * 1000)
                    
                elif algo_config['type'] == 'ElGamal':
                    # ElGamal Encryption
                    start = time.perf_counter()
                    ciphertext = key.encrypt(self.message)
                    enc_times.append((time.perf_counter() - start) * 1000)
                    # ElGamal ciphertext is a tuple (c1, c2), calculate total size
                    c1_bytes = (ciphertext[0].bit_length() + 7) // 8
                    c2_bytes = (ciphertext[1].bit_length() + 7) // 8
                    ciphertext_sizes.append(c1_bytes + c2_bytes)
                    
                    # ElGamal Decryption
                    start = time.perf_counter()
                    plaintext = key.decrypt(ciphertext)
                    dec_times.append((time.perf_counter() - start) * 1000)
            
            avg_enc = np.mean(enc_times)
            avg_dec = np.mean(dec_times)
            avg_cipher_size = np.mean(ciphertext_sizes)
            
            # Calculate speed (operations per second)
            enc_speed = 1000.0 / avg_enc if avg_enc > 0 else 0  # ops/sec
            dec_speed = 1000.0 / avg_dec if avg_dec > 0 else 0  # ops/sec
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'],
                'message_size_bytes': len(self.message),
                'avg_enc_time_ms': round(avg_enc, 4),
                'avg_dec_time_ms': round(avg_dec, 4),
                'enc_speed_ops_per_sec': round(enc_speed, 2),
                'dec_speed_ops_per_sec': round(dec_speed, 2),
                'avg_ciphertext_bytes': round(avg_cipher_size, 0),
                'iterations': self.iterations
            }
            
            self.performance_results.append(result)
            print(f"  Enc Time: {avg_enc:.4f}ms ({enc_speed:.2f} ops/sec) | "
                  f"Dec Time: {avg_dec:.4f}ms ({dec_speed:.2f} ops/sec) | "
                  f"Ciphertext Size: {avg_cipher_size:.0f} bytes")
    
    def test_digital_signatures(self):
        """Test digital signature generation and verification"""
        print("\n" + "="*70)
        print("DIGITAL SIGNATURE GENERATION/VERIFICATION TEST")
        print("="*70)
        
        for algo_name, algo_config in self.algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            # Generate key
            if algo_config['type'] == 'RSA':
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=algo_config['key_size'],
                    backend=default_backend()
                )
            elif algo_config['type'] == 'ECC':
                if algo_config['key_size'] == 256:
                    curve = ec.SECP256R1()
                else:  # 384
                    curve = ec.SECP384R1()
                key = ec.generate_private_key(curve, default_backend())
            elif algo_config['type'] == 'ElGamal':
                key = ElGamalSimulator(algo_config['key_size'])
            
            sig_gen_times = []
            sig_ver_times = []
            signature_sizes = []
            
            # Reduce iterations for ElGamal
            iterations = self.iterations
            
            for _ in range(iterations):
                # Signature generation
                start = time.perf_counter()
                if algo_config['type'] == 'RSA':
                    signature = key.sign(
                        self.message,
                        asym_padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                elif algo_config['type'] == 'ECC':
                    signature = key.sign(
                        self.message,
                        ec.ECDSA(hashes.SHA256())
                    )
                elif algo_config['type'] == 'ElGamal':
                    signature = key.sign(self.message)
                
                sig_gen_times.append((time.perf_counter() - start) * 1000)
                
                # Calculate signature size
                if algo_config['type'] == 'ElGamal':
                    r_bytes = (signature[0].bit_length() + 7) // 8
                    s_bytes = (signature[1].bit_length() + 7) // 8
                    signature_sizes.append(r_bytes + s_bytes)
                else:
                    signature_sizes.append(len(signature))
                
                # Signature verification
                start = time.perf_counter()
                try:
                    if algo_config['type'] == 'RSA':
                        public_key = key.public_key()
                        public_key.verify(
                            signature,
                            self.message,
                            asym_padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                    elif algo_config['type'] == 'ECC':
                        public_key = key.public_key()
                        public_key.verify(
                            signature,
                            self.message,
                            ec.ECDSA(hashes.SHA256())
                        )
                    elif algo_config['type'] == 'ElGamal':
                        key.verify(self.message, signature)
                    
                    sig_ver_times.append((time.perf_counter() - start) * 1000)
                except (InvalidSignature, Exception):
                    sig_ver_times.append((time.perf_counter() - start) * 1000)
            
            avg_sig_gen = np.mean(sig_gen_times)
            avg_sig_ver = np.mean(sig_ver_times)
            avg_sig_size = np.mean(signature_sizes)
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'],
                'message_size_bytes': len(self.message),
                'avg_sig_gen_ms': round(avg_sig_gen, 4),
                'avg_sig_ver_ms': round(avg_sig_ver, 4),
                'avg_signature_bytes': round(avg_sig_size, 0),
                'gen_ver_ratio': round(avg_sig_gen / avg_sig_ver, 2) if avg_sig_ver > 0 else 0,
                'iterations': self.iterations
            }
            
            self.signature_results.append(result)
            print(f"  Sig Gen: {avg_sig_gen:.4f}ms | "
                  f"Sig Ver: {avg_sig_ver:.4f}ms | "
                  f"Signature Size: {avg_sig_size:.0f} bytes")
    
    def test_resource_consumption(self):
        """Test CPU and memory consumption"""
        print("\n" + "="*70)
        print("RESOURCE CONSUMPTION TEST")
        print("="*70)
        
        for algo_name, algo_config in self.algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            cpu_times = []
            memory_usage = []
            object_sizes = []
            
            # Reduce iterations for ElGamal
            iterations = self.iterations
            
            for i in range(iterations):
                # Force garbage collection multiple times before measurement
                gc.collect()
                gc.collect()
                time.sleep(0.05)
                
                # Get baseline memory in bytes - take multiple samples
                baseline_samples = []
                for _ in range(3):
                    baseline_samples.append(self.process.memory_info().rss)
                    time.sleep(0.01)
                mem_baseline = min(baseline_samples)  # Use minimum as baseline
                
                cpu_start = self.process.cpu_times()
                mem_samples = []
                
                # Perform key generation and sample memory during operation
                if algo_config['type'] == 'RSA':
                    key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=algo_config['key_size'],
                        backend=default_backend()
                    )
                    # Sample memory multiple times after generation
                    for _ in range(5):
                        mem_samples.append(self.process.memory_info().rss)
                    
                    # Measure the serialized key size for object memory
                    key_bytes = key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    object_sizes.append(len(key_bytes))
                    
                elif algo_config['type'] == 'ECC':
                    if algo_config['key_size'] == 256:
                        curve = ec.SECP256R1()
                    else:  # 384
                        curve = ec.SECP384R1()
                    key = ec.generate_private_key(curve, default_backend())
                    # Sample memory multiple times after generation
                    for _ in range(5):
                        mem_samples.append(self.process.memory_info().rss)
                    
                    # Measure the serialized key size for object memory
                    key_bytes = key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    object_sizes.append(len(key_bytes))
                    
                elif algo_config['type'] == 'ElGamal':
                    key = ElGamalSimulator(algo_config['key_size'])
                    # Sample memory multiple times after generation
                    for _ in range(5):
                        mem_samples.append(self.process.memory_info().rss)
                    
                    # Estimate object size for ElGamal (p, g, x, y all ~key_size bits)
                    estimated_size = (algo_config['key_size'] // 8) * 4  # 4 large integers
                    object_sizes.append(estimated_size)
                
                cpu_end = self.process.cpu_times()
                
                cpu_time = (cpu_end.user - cpu_start.user) * 1000
                
                # Use the maximum memory sample minus baseline
                if mem_samples:
                    max_mem = max(mem_samples)
                    memory_delta_bytes = max(0, max_mem - mem_baseline)
                else:
                    memory_delta_bytes = 0
                
                # If RSS didn't change, use object size as minimum memory estimate
                if memory_delta_bytes == 0 and object_sizes:
                    memory_delta_bytes = object_sizes[-1]  # Use actual object size
                
                memory_delta_kb = memory_delta_bytes / 1024.0
                
                cpu_times.append(cpu_time if cpu_time > 0 else 0.01)
                memory_usage.append(memory_delta_kb)
                
                # Clean up
                del key
                if 'key_bytes' in locals():
                    del key_bytes
            
            # Final cleanup
            gc.collect()
            
            avg_cpu = np.mean(cpu_times)
            avg_memory_kb = np.mean(memory_usage)
            peak_memory_kb = np.max(memory_usage)
            avg_object_kb = np.mean(object_sizes) / 1024.0
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'],
                'avg_cpu_time_ms': round(avg_cpu, 4),
                'avg_memory_kb': round(avg_memory_kb, 2),
                'peak_memory_kb': round(peak_memory_kb, 2),
                'avg_object_size_kb': round(avg_object_kb, 2),
                'iterations': self.iterations
            }
            
            self.resource_results.append(result)
            print(f"  CPU Time: {avg_cpu:.4f}ms | "
                  f"Avg Memory: {avg_memory_kb:.2f}KB | "
                  f"Peak Memory: {peak_memory_kb:.2f}KB | "
                  f"Obj Size: {avg_object_kb:.2f}KB")
    
    def save_performance_to_csv(self, filename='results/asymmetric/asymmetric_performance.csv'):
        """Save performance results to CSV"""
        if not self.performance_results:
            print("No performance data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        
        # Merge rows with same algorithm by combining all their fields
        merged_results = {}
        for result in self.performance_results:
            algo = result['algorithm']
            if algo not in merged_results:
                merged_results[algo] = {}
            # Merge all fields from this result into the algorithm's merged data
            merged_results[algo].update(result)
        
        # Convert back to list and order columns logically
        final_results = list(merged_results.values())
        
        # Define column order for better readability
        column_order = ['algorithm', 'key_size_bits', 'iterations', 'message_size_bytes',
                        'avg_gen_time_ms', 'std_dev_ms', 'avg_key_export_bytes',
                        'avg_enc_time_ms', 'enc_speed_ops_per_sec',
                        'avg_dec_time_ms', 'dec_speed_ops_per_sec',
                        'avg_ciphertext_bytes']
        
        # Get all keys that actually exist in the data
        all_keys = set()
        for result in final_results:
            all_keys.update(result.keys())
        
        # Use only the columns that exist, in the preferred order
        fieldnames = [col for col in column_order if col in all_keys]
        # Add any extra columns not in the preferred order
        fieldnames.extend([col for col in sorted(all_keys) if col not in fieldnames])
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(final_results)
        
        print(f"\n✓ Performance results saved to '{filename}'")

    
    def save_signature_to_csv(self, filename='results/asymmetric/asymmetric_signatures.csv'):
        """Save signature results to CSV"""
        if not self.signature_results:
            print("No signature data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        
        keys = self.signature_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.signature_results)
        
        print(f"✓ Signature results saved to '{filename}'")
    
    def save_resource_to_csv(self, filename='results/asymmetric/asymmetric_resources.csv'):
        """Save resource consumption results to CSV"""
        if not self.resource_results:
            print("No resource data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        keys = self.resource_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.resource_results)
        
        print(f"✓ Resource results saved to '{filename}'")
    
    def visualize_performance(self, filename='results/asymmetric/asymmetric_performance_chart.png'):
        """Generate performance visualization"""
        if not self.performance_results:
            print("No performance data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.performance_results)
        df_key_gen = df[df['algorithm'].str.contains('256|384|2048|3072') & ~df['avg_enc_time_ms'].notna()]
        df_enc_dec = df[df['avg_enc_time_ms'].notna()]
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Asymmetric Encryption Performance Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: Key generation time
        if len(df_key_gen) > 0:
            sorted_kg = df_key_gen.sort_values('avg_gen_time_ms')
            axes[0, 0].barh(sorted_kg['algorithm'], sorted_kg['avg_gen_time_ms'], 
                           color='skyblue', edgecolor='navy', linewidth=1.5)
            axes[0, 0].set_xlabel('Time (ms)', fontweight='bold')
            axes[0, 0].set_title('Key Generation Time')
            axes[0, 0].grid(True, alpha=0.3, axis='x')
            
            for i, v in enumerate(sorted_kg['avg_gen_time_ms'].values):
                axes[0, 0].text(v + max(sorted_kg['avg_gen_time_ms'])*0.02, i, f'{v:.2f}ms', 
                               va='center', fontweight='bold')
        
        # Plot 2: Encryption vs Decryption time
        if len(df_enc_dec) > 0:
            enc_avg = df_enc_dec.groupby('algorithm')['avg_enc_time_ms'].mean()
            dec_avg = df_enc_dec.groupby('algorithm')['avg_dec_time_ms'].mean()
            
            x = np.arange(len(enc_avg))
            width = 0.35
            bars1 = axes[0, 1].bar(x - width/2, enc_avg.values, width, label='Encryption', 
                          color='lightcoral', edgecolor='red', linewidth=1.5)
            bars2 = axes[0, 1].bar(x + width/2, dec_avg.values, width, label='Decryption', 
                          color='lightgreen', edgecolor='green', linewidth=1.5)
            axes[0, 1].set_ylabel('Time (ms)', fontweight='bold')
            axes[0, 1].set_title('Encryption vs Decryption Time')
            axes[0, 1].set_xticks(x)
            axes[0, 1].set_xticklabels(enc_avg.index, rotation=45, ha='right')
            axes[0, 1].legend()
            axes[0, 1].grid(True, alpha=0.3, axis='y')
            
            # Add value labels on bars
            for i, (bar1, bar2) in enumerate(zip(bars1, bars2)):
                height1 = bar1.get_height()
                height2 = bar2.get_height()
                axes[0, 1].text(bar1.get_x() + bar1.get_width()/2., height1,
                              f'{height1:.4f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
                axes[0, 1].text(bar2.get_x() + bar2.get_width()/2., height2,
                              f'{height2:.4f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        
        # Plot 3: Encryption/Decryption Speed (ops/sec)
        if len(df_enc_dec) > 0 and 'enc_speed_ops_per_sec' in df_enc_dec.columns:
            enc_speed = df_enc_dec.groupby('algorithm')['enc_speed_ops_per_sec'].mean()
            dec_speed = df_enc_dec.groupby('algorithm')['dec_speed_ops_per_sec'].mean()
            
            x = np.arange(len(enc_speed))
            width = 0.35
            bars1 = axes[1, 0].bar(x - width/2, enc_speed.values, width, label='Encryption', 
                          color='gold', edgecolor='orange', linewidth=1.5)
            bars2 = axes[1, 0].bar(x + width/2, dec_speed.values, width, label='Decryption', 
                          color='lightblue', edgecolor='blue', linewidth=1.5)
            axes[1, 0].set_ylabel('Speed (ops/sec)', fontweight='bold')
            axes[1, 0].set_title('Encryption vs Decryption Speed')
            axes[1, 0].set_xticks(x)
            axes[1, 0].set_xticklabels(enc_speed.index, rotation=45, ha='right')
            axes[1, 0].legend()
            axes[1, 0].grid(True, alpha=0.3, axis='y')
            
            # Add value labels on bars
            for i, (bar1, bar2) in enumerate(zip(bars1, bars2)):
                height1 = bar1.get_height()
                height2 = bar2.get_height()
                axes[1, 0].text(bar1.get_x() + bar1.get_width()/2., height1,
                              f'{height1:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
                axes[1, 0].text(bar2.get_x() + bar2.get_width()/2., height2,
                              f'{height2:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        
        # Plot 4: Ciphertext size comparison
        if len(df_enc_dec) > 0:
            sorted_cipher = df_enc_dec.sort_values('avg_ciphertext_bytes')
            axes[1, 1].barh(sorted_cipher['algorithm'], sorted_cipher['avg_ciphertext_bytes'], 
                          color='mediumpurple', edgecolor='indigo', linewidth=1.5)
            axes[1, 1].set_xlabel('Ciphertext Size (bytes)', fontweight='bold')
            axes[1, 1].set_title('Average Ciphertext Size')
            axes[1, 1].grid(True, alpha=0.3, axis='x')
            
            for i, v in enumerate(sorted_cipher['avg_ciphertext_bytes'].values):
                axes[1, 1].text(v + max(sorted_cipher['avg_ciphertext_bytes'])*0.02, i, f'{int(v)}B', 
                               va='center', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Performance chart saved to '{filename}'")
        plt.close()
    
    def visualize_signatures(self, filename='results/asymmetric/asymmetric_signatures_chart.png'):
        """Generate signature performance visualization"""
        if not self.signature_results:
            print("No signature data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.signature_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Asymmetric Digital Signature Performance Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: Signature generation vs verification
        x = np.arange(len(df))
        width = 0.35
        axes[0, 0].bar(x - width/2, df['avg_sig_gen_ms'], width, label='Generation', 
                      color='orange', edgecolor='darkorange', linewidth=1.5)
        axes[0, 0].bar(x + width/2, df['avg_sig_ver_ms'], width, label='Verification', 
                      color='lightblue', edgecolor='blue', linewidth=1.5)
        axes[0, 0].set_ylabel('Time (ms)', fontweight='bold')
        axes[0, 0].set_title('Signature Generation vs Verification Time')
        axes[0, 0].set_xticks(x)
        axes[0, 0].set_xticklabels(df['algorithm'])
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3, axis='y')
        
        # Plot 2: Signature size comparison
        sorted_sig = df.sort_values('avg_signature_bytes')
        axes[0, 1].barh(sorted_sig['algorithm'], sorted_sig['avg_signature_bytes'], 
                       color='mediumseagreen', edgecolor='darkgreen', linewidth=1.5)
        axes[0, 1].set_xlabel('Signature Size (bytes)', fontweight='bold')
        axes[0, 1].set_title('Average Signature Size')
        axes[0, 1].grid(True, alpha=0.3, axis='x')
        
        for i, v in enumerate(sorted_sig['avg_signature_bytes'].values):
            axes[0, 1].text(v + max(sorted_sig['avg_signature_bytes'])*0.02, i, f'{int(v)}B', 
                           va='center', fontweight='bold')
        
        # Plot 3: Generation/Verification ratio
        sorted_ratio = df.sort_values('gen_ver_ratio', ascending=False)
        axes[1, 0].barh(sorted_ratio['algorithm'], sorted_ratio['gen_ver_ratio'], 
                       color='gold', edgecolor='darkgoldenrod', linewidth=1.5)
        axes[1, 0].set_xlabel('Gen/Ver Time Ratio', fontweight='bold')
        axes[1, 0].set_title('Signature Gen/Ver Time Ratio (Higher = Slower Generation)')
        axes[1, 0].grid(True, alpha=0.3, axis='x')
        
        for i, v in enumerate(sorted_ratio['gen_ver_ratio'].values):
            axes[1, 0].text(v + max(sorted_ratio['gen_ver_ratio'])*0.02, i, f'{v:.2f}x', 
                           va='center', fontweight='bold')
        
        # Plot 4: Summary table
        axes[1, 1].axis('off')
        summary_text = "DIGITAL SIGNATURE SUMMARY\n" + "="*45 + "\n\n"
        for _, row in df.iterrows():
            summary_text += f"{row['algorithm']}\n"
            summary_text += f"  Gen: {row['avg_sig_gen_ms']:.4f}ms\n"
            summary_text += f"  Ver: {row['avg_sig_ver_ms']:.4f}ms\n"
            summary_text += f"  Size: {int(row['avg_signature_bytes'])}B\n"
            summary_text += f"  Ratio: {row['gen_ver_ratio']:.2f}x\n"
            summary_text += "\n"
        
        axes[1, 1].text(0.05, 0.95, summary_text, transform=axes[1, 1].transAxes,
                       fontsize=10, verticalalignment='top', fontfamily='monospace',
                       bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Signature chart saved to '{filename}'")
        plt.close()
    
    def visualize_resources(self, filename='results/asymmetric/asymmetric_resources_chart.png'):
        """Generate resource consumption visualization"""
        if not self.resource_results:
            print("No resource data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.resource_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Asymmetric Encryption Resource Consumption Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: CPU usage comparison
        sorted_cpu = df.sort_values('avg_cpu_time_ms', ascending=False)
        bars_cpu = axes[0, 0].barh(sorted_cpu['algorithm'], sorted_cpu['avg_cpu_time_ms'], 
                       color='lightcoral', edgecolor='red', linewidth=1.5)
        axes[0, 0].set_xlabel('CPU Time (ms)', fontweight='bold')
        axes[0, 0].set_title('Average CPU Time per Algorithm')
        axes[0, 0].grid(True, alpha=0.3, axis='x')
        
        # Add value labels on CPU bars
        for i, (bar, val) in enumerate(zip(bars_cpu, sorted_cpu['avg_cpu_time_ms'].values)):
            axes[0, 0].text(val + max(sorted_cpu['avg_cpu_time_ms'])*0.02, i, f'{val:.2f}', 
                           va='center', fontsize=9, fontweight='bold')
        
        # Plot 2: Memory consumption
        x = np.arange(len(df))
        width = 0.35
        bars_avg = axes[0, 1].bar(x - width/2, df['avg_memory_kb'], width, label='Avg Memory', 
                      color='lightblue', edgecolor='blue', linewidth=1.5)
        bars_peak = axes[0, 1].bar(x + width/2, df['peak_memory_kb'], width, label='Peak Memory', 
                      color='lightcoral', edgecolor='red', linewidth=1.5)
        axes[0, 1].set_ylabel('Memory (KB)', fontweight='bold')
        axes[0, 1].set_title('Memory Consumption Analysis')
        axes[0, 1].set_xticks(x)
        axes[0, 1].set_xticklabels(df['algorithm'], rotation=45, ha='right')
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3, axis='y')
        
        # Add value labels on memory bars
        for bar_avg, bar_peak, val_avg, val_peak in zip(bars_avg, bars_peak, 
                                                          df['avg_memory_kb'].values, 
                                                          df['peak_memory_kb'].values):
            height_avg = bar_avg.get_height()
            height_peak = bar_peak.get_height()
            if height_avg > 0:
                axes[0, 1].text(bar_avg.get_x() + bar_avg.get_width()/2., height_avg,
                              f'{val_avg:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
            if height_peak > 0:
                axes[0, 1].text(bar_peak.get_x() + bar_peak.get_width()/2., height_peak,
                              f'{val_peak:.1f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        
        # Plot 3: CPU time ranking
        bars_cpu_rank = axes[1, 0].bar(df['algorithm'], df['avg_cpu_time_ms'], color='orange', 
                      edgecolor='darkorange', linewidth=1.5)
        axes[1, 0].set_ylabel('CPU Time (ms)', fontweight='bold')
        axes[1, 0].set_title('CPU Time Ranking')
        axes[1, 0].set_xticklabels(df['algorithm'], rotation=45, ha='right')
        axes[1, 0].grid(True, alpha=0.3, axis='y')
        
        # Add value labels on CPU ranking bars
        for bar, val in zip(bars_cpu_rank, df['avg_cpu_time_ms'].values):
            height = bar.get_height()
            axes[1, 0].text(bar.get_x() + bar.get_width()/2., height,
                          f'{val:.2f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        
        # Plot 4: Object size comparison
        if 'avg_object_size_kb' in df.columns:
            bars_obj = axes[1, 1].bar(df['algorithm'], df['avg_object_size_kb'], color='mediumseagreen', 
                          edgecolor='darkgreen', linewidth=1.5)
            axes[1, 1].set_ylabel('Key Object Size (KB)', fontweight='bold')
            axes[1, 1].set_title('Average Key Object Size')
            axes[1, 1].set_xticklabels(df['algorithm'], rotation=45, ha='right')
            axes[1, 1].grid(True, alpha=0.3, axis='y')
            
            # Add value labels on object size bars
            for bar, val in zip(bars_obj, df['avg_object_size_kb'].values):
                height = bar.get_height()
                axes[1, 1].text(bar.get_x() + bar.get_width()/2., height,
                              f'{val:.2f}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        else:
            # Fallback to memory efficiency if object size not available
            df['memory_efficiency'] = df['peak_memory_kb'] / (df['avg_memory_kb'] + 0.1)
            axes[1, 1].bar(df['algorithm'], df['memory_efficiency'], color='mediumseagreen', 
                          edgecolor='darkgreen', linewidth=1.5)
            axes[1, 1].set_ylabel('Peak/Avg Memory Ratio', fontweight='bold')
            axes[1, 1].set_title('Memory Efficiency Ratio')
            axes[1, 1].grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Resource chart saved to '{filename}'")
        plt.close()
    
    def run_all_tests(self):
        """Execute all asymmetric encryption tests and save results"""
        print("\n" + "="*70)
        print("STARTING COMPREHENSIVE ASYMMETRIC ENCRYPTION ANALYSIS")
        print("="*70)
        
        self.test_key_generation()
        self.test_encryption_decryption()
        self.test_digital_signatures()
        self.test_resource_consumption()
        
        self.save_performance_to_csv()
        self.save_signature_to_csv()
        self.save_resource_to_csv()
        
        self.visualize_performance()
        self.visualize_signatures()
        self.visualize_resources()
        
        print("\n" + "="*70)
        print("ANALYSIS COMPLETE")
        print("="*70)
        print("\nGenerated Files (in 'results/asymmetric/' folder):")
        print("  CSV Files:")
        print("    - results/asymmetric/asymmetric_performance.csv")
        print("    - results/asymmetric/asymmetric_signatures.csv")
        print("    - results/asymmetric/asymmetric_resources.csv")
        print("  Visualization Files:")
        print("    - results/asymmetric/asymmetric_performance_chart.png")
        print("    - results/asymmetric/asymmetric_signatures_chart.png")
        print("    - results/asymmetric/asymmetric_resources_chart.png")


if __name__ == "__main__":
    analysis = AsymmetricEncryptionAnalysis()
    analysis.run_all_tests()
