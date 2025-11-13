"""
Asymmetric Encryption Algorithm Performance Testing Script
Comparative analysis of RSA-2048, RSA-3072, ECC-256, ECC-384, and ElGamal-2048/3072
Tests: Performance Speed, Resource Consumption, Digital Signatures

Note: ElGamal uses a simulated implementation for performance testing purposes.
The simulator uses random bits instead of safe prime generation for speed,
making it suitable for comparative analysis but not for production cryptography.
"""

import os
import csv
import time
import psutil
import gc
import random
import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib

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
        self.iterations = 20  # Fewer iterations due to computational intensity
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
        """Test encryption/decryption performance"""
        print("\n" + "="*70)
        print("ASYMMETRIC ENCRYPTION/DECRYPTION TEST")
        print("="*70)
        
        enc_dec_algorithms = {k: v for k, v in self.algorithms.items() 
                             if v['type'] in ['RSA', 'ElGamal']}
        
        for algo_name, algo_config in enc_dec_algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            # Generate key once
            if algo_config['type'] == 'RSA':
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=algo_config['key_size'],
                    backend=default_backend()
                )
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
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'],
                'message_size_bytes': len(self.message),
                'avg_enc_time_ms': round(avg_enc, 4),
                'avg_dec_time_ms': round(avg_dec, 4),
                'avg_ciphertext_bytes': round(avg_cipher_size, 0),
                'iterations': self.iterations
            }
            
            self.performance_results.append(result)
            print(f"  Enc Time: {avg_enc:.4f}ms | "
                  f"Dec Time: {avg_dec:.4f}ms | "
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
            
            # Force garbage collection and establish baseline
            gc.collect()
            time.sleep(0.1)  # Let things settle
            
            # Take multiple baseline measurements
            baselines = []
            for _ in range(5):
                baselines.append(self.process.memory_info().rss / (1024 * 1024))
                time.sleep(0.01)
            baseline_memory = np.median(baselines)
            
            # Reduce iterations for ElGamal
            iterations = self.iterations
            
            for i in range(iterations):
                # Force garbage collection before measurement
                gc.collect()
                
                cpu_start = self.process.cpu_times()
                mem_before = self.process.memory_info().rss / (1024 * 1024)
                
                # Perform key generation
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
                
                mem_after = self.process.memory_info().rss / (1024 * 1024)
                cpu_end = self.process.cpu_times()
                
                cpu_time = (cpu_end.user - cpu_start.user) * 1000
                # Use the difference from baseline instead of just before/after
                memory_delta = max(0, mem_after - baseline_memory)
                
                cpu_times.append(cpu_time if cpu_time > 0 else 0.01)
                memory_usage.append(memory_delta)
                
                # Clean up for next iteration
                del key
            
            avg_cpu = np.mean(cpu_times)
            avg_memory = np.mean(memory_usage)
            peak_memory = np.max(memory_usage)
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'],
                'avg_cpu_time_ms': round(avg_cpu, 4),
                'avg_memory_mb': round(avg_memory, 4),
                'peak_memory_mb': round(peak_memory, 4),
                'iterations': self.iterations
            }
            
            self.resource_results.append(result)
            print(f"  CPU Time: {avg_cpu:.4f}ms | "
                  f"Avg Memory: {avg_memory:.4f}MB | "
                  f"Peak Memory: {peak_memory:.4f}MB")
    
    def save_performance_to_csv(self, filename='results/asymmetric/asymmetric_performance.csv'):
        """Save performance results to CSV"""
        if not self.performance_results:
            print("No performance data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/asymmetric', exist_ok=True)
        
        # Collect all unique field names from all results
        all_keys = set()
        for result in self.performance_results:
            all_keys.update(result.keys())
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
            writer.writeheader()
            writer.writerows(self.performance_results)
        
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
            axes[0, 1].bar(x - width/2, enc_avg.values, width, label='Encryption', 
                          color='lightcoral', edgecolor='red', linewidth=1.5)
            axes[0, 1].bar(x + width/2, dec_avg.values, width, label='Decryption', 
                          color='lightgreen', edgecolor='green', linewidth=1.5)
            axes[0, 1].set_ylabel('Time (ms)', fontweight='bold')
            axes[0, 1].set_title('Encryption vs Decryption Time')
            axes[0, 1].set_xticks(x)
            axes[0, 1].set_xticklabels(enc_avg.index)
            axes[0, 1].legend()
            axes[0, 1].grid(True, alpha=0.3, axis='y')
        
        # Plot 3: Ciphertext size comparison
        if len(df_enc_dec) > 0:
            axes[1, 0].bar(df_enc_dec['algorithm'], df_enc_dec['avg_ciphertext_bytes'], 
                          color='mediumpurple', edgecolor='indigo', linewidth=1.5)
            axes[1, 0].set_ylabel('Ciphertext Size (bytes)', fontweight='bold')
            axes[1, 0].set_title('Average Ciphertext Size')
            axes[1, 0].grid(True, alpha=0.3, axis='y')
            
            for i, v in enumerate(df_enc_dec['avg_ciphertext_bytes'].values):
                axes[1, 0].text(i, v + max(df_enc_dec['avg_ciphertext_bytes'])*0.02, f'{int(v)}B', 
                               ha='center', fontweight='bold')
        
        # Plot 4: Key size vs performance
        if len(df_key_gen) > 0:
            sorted_ks = df_key_gen.sort_values('key_size_bits')
            axes[1, 1].plot(sorted_ks['key_size_bits'], sorted_ks['avg_gen_time_ms'], 
                           marker='o', linewidth=2, markersize=8, color='darkblue')
            axes[1, 1].set_xlabel('Key Size (bits)', fontweight='bold')
            axes[1, 1].set_ylabel('Generation Time (ms)', fontweight='bold')
            axes[1, 1].set_title('Key Generation Time vs Key Size')
            axes[1, 1].grid(True, alpha=0.3)
        
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
        axes[0, 0].barh(sorted_cpu['algorithm'], sorted_cpu['avg_cpu_time_ms'], 
                       color='lightcoral', edgecolor='red', linewidth=1.5)
        axes[0, 0].set_xlabel('CPU Time (ms)', fontweight='bold')
        axes[0, 0].set_title('Average CPU Time per Algorithm')
        axes[0, 0].grid(True, alpha=0.3, axis='x')
        
        # Plot 2: Memory consumption
        x = np.arange(len(df))
        width = 0.35
        axes[0, 1].bar(x - width/2, df['avg_memory_mb'], width, label='Avg Memory', 
                      color='lightblue', edgecolor='blue', linewidth=1.5)
        axes[0, 1].bar(x + width/2, df['peak_memory_mb'], width, label='Peak Memory', 
                      color='lightcoral', edgecolor='red', linewidth=1.5)
        axes[0, 1].set_ylabel('Memory (MB)', fontweight='bold')
        axes[0, 1].set_title('Memory Consumption Analysis')
        axes[0, 1].set_xticks(x)
        axes[0, 1].set_xticklabels(df['algorithm'])
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3, axis='y')
        
        # Plot 3: CPU time ranking
        axes[1, 0].bar(df['algorithm'], df['avg_cpu_time_ms'], color='orange', 
                      edgecolor='darkorange', linewidth=1.5)
        axes[1, 0].set_ylabel('CPU Time (ms)', fontweight='bold')
        axes[1, 0].set_title('CPU Time Ranking')
        axes[1, 0].grid(True, alpha=0.3, axis='y')
        
        # Plot 4: Memory efficiency
        df['memory_efficiency'] = df['peak_memory_mb'] / (df['avg_memory_mb'] + 0.001)
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
