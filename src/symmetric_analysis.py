"""
Symmetric Encryption Algorithm Performance Testing Script
Comparative analysis of AES-128, AES-256, DES, 3DES, and Blowfish
Tests: Performance Speed, Resource Consumption, Key Schedule Efficiency
"""

import os
import csv
import time
import psutil
import gc
import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as crypto_padding

class SymmetricEncryptionAnalysis:
    """Comprehensive symmetric encryption analysis with performance measurement"""
    
    def __init__(self):
        self.algorithms = {
            'AES-128': {'key_size': 16, 'algorithm': algorithms.AES, 'block_size': 128},
            'AES-256': {'key_size': 32, 'algorithm': algorithms.AES, 'block_size': 128},
            'DES': {'key_size': 8, 'algorithm': algorithms.TripleDES, 'block_size': 64, 'is_des': True},
            '3DES': {'key_size': 24, 'algorithm': algorithms.TripleDES, 'block_size': 64},
            'Blowfish': {'key_size': 16, 'algorithm': algorithms.Blowfish, 'block_size': 64}
        }
        self.data_sizes = [256, 1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024]  # 256B to 10MB
        self.iterations = 100
        self.performance_results = []
        self.resource_results = []
        self.key_schedule_results = []
        self.process = psutil.Process(os.getpid())
    
    def generate_test_data(self, size):
        """Generate random test data"""
        return os.urandom(size)
    
    def test_performance_speed(self):
        """Test encryption/decryption speed for each algorithm"""
        print("\n" + "="*70)
        print("SYMMETRIC ENCRYPTION PERFORMANCE SPEED TEST")
        print("="*70)
        
        for algo_name, algo_config in self.algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            for data_size in self.data_sizes:
                key = os.urandom(algo_config['key_size'])
                plaintext = self.generate_test_data(data_size)
                
                enc_times = []
                dec_times = []
                
                for _ in range(self.iterations):
                    # Encryption test
                    start = time.perf_counter()
                    iv = os.urandom(algo_config['block_size'] // 8)
                    
                    # Handle DES (which needs 8-byte key for single DES)
                    if algo_config.get('is_des'):
                        # For DES, we'll use first 8 bytes and repeat it 3 times for TripleDES
                        cipher_key = key[:8] * 3
                        cipher_algo = algo_config['algorithm'](cipher_key[:24])
                    else:
                        cipher_algo = algo_config['algorithm'](key)
                    
                    cipher = Cipher(cipher_algo, modes.CBC(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    
                    # Pad the plaintext
                    padder = crypto_padding.PKCS7(algo_config['block_size']).padder()
                    padded = padder.update(plaintext) + padder.finalize()
                    
                    ciphertext = encryptor.update(padded) + encryptor.finalize()
                    
                    enc_times.append((time.perf_counter() - start) * 1000)
                    
                    # Decryption test
                    start = time.perf_counter()
                    
                    if algo_config.get('is_des'):
                        cipher_key = key[:8] * 3
                        cipher_algo = algo_config['algorithm'](cipher_key[:24])
                    else:
                        cipher_algo = algo_config['algorithm'](key)
                    
                    cipher_dec = Cipher(cipher_algo, modes.CBC(iv), backend=default_backend())
                    decryptor = cipher_dec.decryptor()
                    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
                    
                    # Unpad the decrypted data
                    unpadder = crypto_padding.PKCS7(algo_config['block_size']).unpadder()
                    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
                    
                    dec_times.append((time.perf_counter() - start) * 1000)
                
                avg_enc_time = np.mean(enc_times)
                avg_dec_time = np.mean(dec_times)
                enc_throughput = (data_size / (1024 * 1024)) / (avg_enc_time / 1000) if avg_enc_time > 0 else 0
                dec_throughput = (data_size / (1024 * 1024)) / (avg_dec_time / 1000) if avg_dec_time > 0 else 0
                total_throughput = (data_size / (1024 * 1024)) / ((avg_enc_time + avg_dec_time) / 1000)
                
                result = {
                    'algorithm': algo_name,
                    'key_size_bits': algo_config['key_size'] * 8,
                    'data_size_kb': data_size / 1024,
                    'enc_time_ms': round(avg_enc_time, 4),
                    'dec_time_ms': round(avg_dec_time, 4),
                    'total_time_ms': round(avg_enc_time + avg_dec_time, 4),
                    'enc_throughput_mbps': round(enc_throughput, 2),
                    'dec_throughput_mbps': round(dec_throughput, 2),
                    'total_throughput_mbps': round(total_throughput, 2),
                    'iterations': self.iterations
                }
                
                self.performance_results.append(result)
                print(f"  Data Size: {data_size/1024:.1f}KB | "
                      f"Enc: {avg_enc_time:.4f}ms | "
                      f"Dec: {avg_dec_time:.4f}ms | "
                      f"Throughput: {total_throughput:.2f} MBps")
    
    def test_resource_consumption(self):
        """Test CPU and memory consumption"""
        print("\n" + "="*70)
        print("RESOURCE CONSUMPTION TEST")
        print("="*70)
        
        test_data = self.generate_test_data(10*1024*1024)  # 10MB test data
        
        for algo_name, algo_config in self.algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            key = os.urandom(algo_config['key_size'])
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
            
            for iteration in range(self.iterations):
                # Force garbage collection before measurement
                gc.collect()
                
                cpu_start = self.process.cpu_times()
                mem_before = self.process.memory_info().rss / (1024 * 1024)
                
                # Perform encryption
                iv = os.urandom(algo_config['block_size'] // 8)
                
                if algo_config.get('is_des'):
                    cipher_key = key[:8] * 3
                    cipher_algo = algo_config['algorithm'](cipher_key[:24])
                else:
                    cipher_algo = algo_config['algorithm'](key)
                
                cipher = Cipher(cipher_algo, modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                padder = crypto_padding.PKCS7(algo_config['block_size']).padder()
                padded = padder.update(test_data) + padder.finalize()
                ciphertext = encryptor.update(padded) + encryptor.finalize()
                
                # Perform decryption
                if algo_config.get('is_des'):
                    cipher_key = key[:8] * 3
                    cipher_algo = algo_config['algorithm'](cipher_key[:24])
                else:
                    cipher_algo = algo_config['algorithm'](key)
                
                cipher_dec = Cipher(cipher_algo, modes.CBC(iv), backend=default_backend())
                decryptor = cipher_dec.decryptor()
                decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
                
                unpadder = crypto_padding.PKCS7(algo_config['block_size']).unpadder()
                decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
                
                mem_after = self.process.memory_info().rss / (1024 * 1024)
                cpu_end = self.process.cpu_times()
                
                cpu_time = (cpu_end.user - cpu_start.user) * 1000
                # Use the difference from baseline instead of just before/after
                memory_delta = max(0, mem_after - baseline_memory)
                
                cpu_times.append(cpu_time if cpu_time > 0 else 0.01)
                memory_usage.append(memory_delta)
                
                # Clean up for next iteration
                del cipher, cipher_dec, padded, ciphertext, decrypted, iv, encryptor, decryptor
            
            avg_cpu = np.mean(cpu_times)
            avg_memory = np.mean(memory_usage)
            peak_memory = np.max(memory_usage)
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'] * 8,
                'data_size_mb': test_data.__sizeof__() / (1024 * 1024),
                'avg_cpu_time_ms': round(avg_cpu, 4),
                'avg_memory_mb': round(avg_memory, 4),
                'peak_memory_mb': round(peak_memory, 4),
                'iterations': self.iterations
            }
            
            self.resource_results.append(result)
            print(f"  CPU Time: {avg_cpu:.4f}ms | "
                  f"Avg Memory: {avg_memory:.4f}MB | "
                  f"Peak Memory: {peak_memory:.4f}MB")
    
    def test_key_schedule_efficiency(self):
        """Test key schedule and IV generation efficiency"""
        print("\n" + "="*70)
        print("KEY SCHEDULE AND IV GENERATION EFFICIENCY TEST")
        print("="*70)
        
        test_data = self.generate_test_data(1024*1024)  # 1MB test data
        
        for algo_name, algo_config in self.algorithms.items():
            print(f"\nTesting {algo_name}...")
            
            key = os.urandom(algo_config['key_size'])
            
            # Test key schedule overhead (cipher object creation)
            key_schedule_times = []
            iv_generation_times = []
            cipher_creation_times = []
            
            for _ in range(self.iterations):
                # Cipher object creation time
                start = time.perf_counter()
                iv = os.urandom(algo_config['block_size'] // 8)
                
                if algo_config.get('is_des'):
                    cipher_key = key[:8] * 3
                    cipher_algo = algo_config['algorithm'](cipher_key[:24])
                else:
                    cipher_algo = algo_config['algorithm'](key)
                
                cipher = Cipher(cipher_algo, modes.CBC(iv), backend=default_backend())
                cipher_creation_times.append((time.perf_counter() - start) * 1000000)  # microseconds
                
                iv_generation_times.append(len(iv))
            
            # Estimate actual encryption overhead vs key schedule
            start = time.perf_counter()
            iv = os.urandom(algo_config['block_size'] // 8)
            
            if algo_config.get('is_des'):
                cipher_key = key[:8] * 3
                cipher_algo = algo_config['algorithm'](cipher_key[:24])
            else:
                cipher_algo = algo_config['algorithm'](key)
            
            cipher = Cipher(cipher_algo, modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = crypto_padding.PKCS7(algo_config['block_size']).padder()
            padded = padder.update(test_data) + padder.finalize()
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            
            total_time = (time.perf_counter() - start) * 1000  # milliseconds
            key_schedule_overhead = np.mean(cipher_creation_times)
            
            result = {
                'algorithm': algo_name,
                'key_size_bits': algo_config['key_size'] * 8,
                'cipher_creation_us': round(key_schedule_overhead, 4),
                'iv_size_bytes': np.mean(iv_generation_times),
                'total_enc_ms': round(total_time, 4),
                'key_schedule_overhead_percent': round((key_schedule_overhead / (total_time * 1000)) * 100, 2),
                'iterations': self.iterations
            }
            
            self.key_schedule_results.append(result)
            print(f"  Cipher Creation: {key_schedule_overhead:.4f}µs | "
                  f"IV Size: {int(np.mean(iv_generation_times))} bytes | "
                  f"Overhead: {result['key_schedule_overhead_percent']:.2f}%")
    
    def save_performance_to_csv(self, filename='results/symmetric/symmetric_performance.csv'):
        """Save performance results to CSV"""
        if not self.performance_results:
            print("No performance data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/symmetric', exist_ok=True)
        
        keys = self.performance_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.performance_results)
        
        print(f"\n✓ Performance results saved to '{filename}'")
    
    def save_resource_to_csv(self, filename='results/symmetric/symmetric_resources.csv'):
        """Save resource consumption results to CSV"""
        if not self.resource_results:
            print("No resource data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/symmetric', exist_ok=True)
        
        keys = self.resource_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.resource_results)
        
        print(f"✓ Resource results saved to '{filename}'")
    
    def save_key_schedule_to_csv(self, filename='results/symmetric/symmetric_key_schedule.csv'):
        """Save key schedule results to CSV"""
        if not self.key_schedule_results:
            print("No key schedule data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/symmetric', exist_ok=True)
        
        keys = self.key_schedule_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.key_schedule_results)
        
        print(f"✓ Key schedule results saved to '{filename}'")
    
    def visualize_performance(self, filename='results/symmetric/symmetric_performance_chart.png'):
        """Generate performance visualization"""
        if not self.performance_results:
            print("No performance data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/symmetric', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.performance_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Symmetric Encryption Performance Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: Encryption throughput by data size
        for algo in df['algorithm'].unique():
            algo_data = df[df['algorithm'] == algo].sort_values('data_size_kb')
            axes[0, 0].plot(algo_data['data_size_kb'], algo_data['enc_throughput_mbps'], 
                           marker='o', label=algo, linewidth=2)
        
        axes[0, 0].set_xlabel('Data Size (KB)', fontweight='bold')
        axes[0, 0].set_ylabel('Throughput (MBps)', fontweight='bold')
        axes[0, 0].set_title('Encryption Throughput vs Data Size')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].set_xscale('log')
        
        # Plot 2: Encryption vs Decryption time
        enc_avg = df.groupby('algorithm')['enc_time_ms'].mean()
        dec_avg = df.groupby('algorithm')['dec_time_ms'].mean()
        
        x = np.arange(len(enc_avg))
        width = 0.35
        axes[0, 1].bar(x - width/2, enc_avg.values, width, label='Encryption', 
                      color='lightblue', edgecolor='blue', linewidth=1.5)
        axes[0, 1].bar(x + width/2, dec_avg.values, width, label='Decryption', 
                      color='lightcoral', edgecolor='red', linewidth=1.5)
        axes[0, 1].set_ylabel('Time (ms)', fontweight='bold')
        axes[0, 1].set_title('Encryption vs Decryption Time')
        axes[0, 1].set_xticks(x)
        axes[0, 1].set_xticklabels(enc_avg.index)
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3, axis='y')
        
        # Plot 3: Total throughput comparison (largest data size)
        largest_data = df[df['data_size_kb'] == df['data_size_kb'].max()]
        axes[1, 0].barh(largest_data['algorithm'], largest_data['total_throughput_mbps'], 
                       color='lightgreen', edgecolor='darkgreen', linewidth=1.5)
        axes[1, 0].set_xlabel('Throughput (MBps)', fontweight='bold')
        axes[1, 0].set_title('Total Throughput at Maximum Data Size (10MB)')
        axes[1, 0].grid(True, alpha=0.3, axis='x')
        
        for i, v in enumerate(largest_data['total_throughput_mbps'].values):
            axes[1, 0].text(v + max(largest_data['total_throughput_mbps'])*0.02, i, f'{v:.2f}', 
                           va='center', fontweight='bold')
        
        # Plot 4: Total time comparison
        total_avg = df.groupby('algorithm')['total_time_ms'].mean().sort_values(ascending=False)
        axes[1, 1].bar(total_avg.index, total_avg.values, color='gold', edgecolor='darkgoldenrod', linewidth=1.5)
        axes[1, 1].set_ylabel('Total Time (ms)', fontweight='bold')
        axes[1, 1].set_title('Average Total Encryption/Decryption Time')
        axes[1, 1].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(total_avg.values):
            axes[1, 1].text(i, v + max(total_avg)*0.02, f'{v:.4f}', ha='center', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Performance chart saved to '{filename}'")
        plt.close()
    
    def visualize_resources(self, filename='results/symmetric/symmetric_resources_chart.png'):
        """Generate resource consumption visualization"""
        if not self.resource_results:
            print("No resource data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/symmetric', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.resource_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Symmetric Encryption Resource Consumption Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: CPU usage comparison
        axes[0, 0].bar(df['algorithm'], df['avg_cpu_time_ms'], color='orange', 
                      edgecolor='darkorange', linewidth=1.5)
        axes[0, 0].set_ylabel('CPU Time (ms)', fontweight='bold')
        axes[0, 0].set_title('Average CPU Time per Algorithm')
        axes[0, 0].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(df['avg_cpu_time_ms'].values):
            axes[0, 0].text(i, v + max(df['avg_cpu_time_ms'])*0.02, f'{v:.4f}', 
                           ha='center', fontweight='bold')
        
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
        sorted_cpu = df.sort_values('avg_cpu_time_ms', ascending=False)
        axes[1, 0].barh(sorted_cpu['algorithm'], sorted_cpu['avg_cpu_time_ms'], 
                       color='gold', edgecolor='darkgoldenrod', linewidth=1.5)
        axes[1, 0].set_xlabel('CPU Time (ms)', fontweight='bold')
        axes[1, 0].set_title('CPU Time Ranking (Higher = Slower)')
        axes[1, 0].grid(True, alpha=0.3, axis='x')
        
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
    
    def visualize_key_schedule(self, filename='results/symmetric/symmetric_key_schedule_chart.png'):
        """Generate key schedule efficiency visualization"""
        if not self.key_schedule_results:
            print("No key schedule data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/symmetric', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.key_schedule_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Symmetric Encryption Key Schedule & IV Efficiency', fontsize=16, fontweight='bold')
        
        # Plot 1: Cipher creation time
        axes[0, 0].bar(df['algorithm'], df['cipher_creation_us'], color='purple', 
                      edgecolor='indigo', linewidth=1.5)
        axes[0, 0].set_ylabel('Time (µs)', fontweight='bold')
        axes[0, 0].set_title('Cipher Object Creation Time')
        axes[0, 0].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(df['cipher_creation_us'].values):
            axes[0, 0].text(i, v + max(df['cipher_creation_us'])*0.02, f'{v:.4f}µs', 
                           ha='center', fontweight='bold')
        
        # Plot 2: IV size comparison
        axes[0, 1].bar(df['algorithm'], df['iv_size_bytes'], color='teal', 
                      edgecolor='darkslategray', linewidth=1.5)
        axes[0, 1].set_ylabel('IV Size (bytes)', fontweight='bold')
        axes[0, 1].set_title('Initialization Vector Size')
        axes[0, 1].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(df['iv_size_bytes'].values):
            axes[0, 1].text(i, v + max(df['iv_size_bytes'])*0.02, f'{int(v)}B', 
                           ha='center', fontweight='bold')
        
        # Plot 3: Key schedule overhead percentage
        axes[1, 0].barh(df['algorithm'], df['key_schedule_overhead_percent'], 
                       color='salmon', edgecolor='crimson', linewidth=1.5)
        axes[1, 0].set_xlabel('Overhead (%)', fontweight='bold')
        axes[1, 0].set_title('Key Schedule Overhead Percentage')
        axes[1, 0].grid(True, alpha=0.3, axis='x')
        
        for i, v in enumerate(df['key_schedule_overhead_percent'].values):
            axes[1, 0].text(v + max(df['key_schedule_overhead_percent'])*0.02, i, f'{v:.2f}%', 
                           va='center', fontweight='bold')
        
        # Plot 4: Summary table
        axes[1, 1].axis('off')
        summary_text = "KEY SCHEDULE EFFICIENCY SUMMARY\n" + "="*45 + "\n\n"
        for _, row in df.iterrows():
            summary_text += f"{row['algorithm']}\n"
            summary_text += f"  Creation: {row['cipher_creation_us']:.4f}µs\n"
            summary_text += f"  IV Size: {int(row['iv_size_bytes'])} bytes\n"
            summary_text += f"  Overhead: {row['key_schedule_overhead_percent']:.2f}%\n"
            summary_text += "\n"
        
        axes[1, 1].text(0.05, 0.95, summary_text, transform=axes[1, 1].transAxes,
                       fontsize=10, verticalalignment='top', fontfamily='monospace',
                       bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Key schedule chart saved to '{filename}'")
        plt.close()
    
    def run_all_tests(self):
        """Execute all symmetric encryption tests and save results"""
        print("\n" + "="*70)
        print("STARTING COMPREHENSIVE SYMMETRIC ENCRYPTION ANALYSIS")
        print("="*70)
        
        self.test_performance_speed()
        self.test_resource_consumption()
        self.test_key_schedule_efficiency()
        
        self.save_performance_to_csv()
        self.save_resource_to_csv()
        self.save_key_schedule_to_csv()
        
        self.visualize_performance()
        self.visualize_resources()
        self.visualize_key_schedule()
        
        print("\n" + "="*70)
        print("ANALYSIS COMPLETE")
        print("="*70)
        print("\nGenerated Files (in 'results/symmetric/' folder):")
        print("  CSV Files:")
        print("    - results/symmetric/symmetric_performance.csv")
        print("    - results/symmetric/symmetric_resources.csv")
        print("    - results/symmetric/symmetric_key_schedule.csv")
        print("  Visualization Files:")
        print("    - results/symmetric/symmetric_performance_chart.png")
        print("    - results/symmetric/symmetric_resources_chart.png")
        print("    - results/symmetric/symmetric_key_schedule_chart.png")


if __name__ == "__main__":
    analysis = SymmetricEncryptionAnalysis()
    analysis.run_all_tests()
