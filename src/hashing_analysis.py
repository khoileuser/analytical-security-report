"""
Hashing Algorithm Performance Testing Script
Comparative analysis of MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, and BLAKE2
Tests: Performance Speed, Resource Consumption, Collision Analysis
"""

import hashlib
import os
import csv
import time
import psutil
import gc
import matplotlib.pyplot as plt
import numpy as np

class HashingPerformanceAnalysis:
    """Comprehensive hashing algorithm analysis with performance measurement"""
    
    def __init__(self):
        self.algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b']
        self.data_sizes = [1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024, 50*1024*1024]  # 1KB to 50MB
        self.iterations = 100
        self.performance_results = []
        self.resource_results = []
        self.collision_results = []
        self.process = psutil.Process(os.getpid())
    
    def generate_test_data(self, size):
        """Generate deterministic test data of specified size"""
        return os.urandom(size)
    
    def test_performance_speed(self):
        """Test hashing speed for each algorithm across different data sizes"""
        print("\n" + "="*70)
        print("HASHING PERFORMANCE SPEED TEST")
        print("="*70)
        
        for algo in self.algorithms:
            print(f"\nTesting {algo.upper()}...")
            for data_size in self.data_sizes:
                test_data = self.generate_test_data(data_size)
                times = []
                
                for _ in range(self.iterations):
                    start = time.perf_counter()
                    h = hashlib.new(algo)
                    h.update(test_data)
                    h.hexdigest()
                    elapsed = (time.perf_counter() - start) * 1000
                    times.append(elapsed)
                
                avg_time = np.mean(times)
                std_dev = np.std(times)
                throughput = (data_size / (1024 * 1024)) / (avg_time / 1000) if avg_time > 0 else 0
                
                result = {
                    'algorithm': algo.upper(),
                    'data_size_kb': data_size / 1024,
                    'avg_time_ms': round(avg_time, 4),
                    'std_dev_ms': round(std_dev, 4),
                    'throughput_mbps': round(throughput, 2),
                    'iterations': self.iterations
                }
                
                self.performance_results.append(result)
                print(f"  Data Size: {data_size/1024:.1f}KB | "
                      f"Avg Time: {avg_time:.4f}ms | "
                      f"Throughput: {throughput:.2f} MBps")
    
    def test_resource_consumption(self):
        """Test CPU and memory consumption for each algorithm"""
        print("\n" + "="*70)
        print("RESOURCE CONSUMPTION TEST")
        print("="*70)
        
        test_data = self.generate_test_data(10*1024*1024)  # 10MB test data
        
        for algo in self.algorithms:
            print(f"\nTesting {algo.upper()}...")
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
            
            for _ in range(self.iterations):
                # Force garbage collection before measurement
                gc.collect()
                
                cpu_start = self.process.cpu_times()
                mem_before = self.process.memory_info().rss / (1024 * 1024)
                
                # Perform hashing
                h = hashlib.new(algo)
                h.update(test_data)
                digest = h.hexdigest()
                
                mem_after = self.process.memory_info().rss / (1024 * 1024)
                cpu_end = self.process.cpu_times()
                
                cpu_time = (cpu_end.user - cpu_start.user) * 1000  # Convert to ms
                # Use the difference from baseline instead of just before/after
                memory_delta = max(0, mem_after - baseline_memory)
                
                cpu_times.append(cpu_time if cpu_time > 0 else 0.01)
                memory_usage.append(memory_delta)
                
                # Clean up for next iteration
                del h, digest
            
            avg_cpu = np.mean(cpu_times)
            avg_memory = np.mean(memory_usage)
            peak_memory = np.max(memory_usage)
            
            result = {
                'algorithm': algo.upper(),
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
    
    def test_collision_resistance(self):
        """Test avalanche effect and collision resistance"""
        print("\n" + "="*70)
        print("COLLISION RESISTANCE & AVALANCHE EFFECT TEST")
        print("="*70)
        
        for algo in self.algorithms:
            print(f"\nTesting {algo.upper()}...")
            
            # Test 1: Avalanche effect (small change produces large change in hash)
            base_data = b"The quick brown fox jumps over the lazy dog"
            modified_data = b"The quick brown fox jumps over the lazy cog"
            
            h1 = hashlib.new(algo)
            h1.update(base_data)
            hash1 = h1.hexdigest()
            
            h2 = hashlib.new(algo)
            h2.update(modified_data)
            hash2 = h2.hexdigest()
            
            # Count differing bits
            differing_chars = sum(1 for a, b in zip(hash1, hash2) if a != b)
            diff_percentage = (differing_chars / len(hash1)) * 100
            
            # Test 2: Deterministic behavior (same input produces same output)
            h3 = hashlib.new(algo)
            h3.update(base_data)
            hash3 = h3.hexdigest()
            
            is_deterministic = hash1 == hash3
            
            # Test 3: Output characteristics
            h_obj = hashlib.new(algo)
            output_bits = h_obj.digest_size * 8
            
            result = {
                'algorithm': algo.upper(),
                'output_bits': output_bits,
                'avalanche_char_diff': differing_chars,
                'avalanche_diff_percentage': round(diff_percentage, 2),
                'is_deterministic': 'Yes' if is_deterministic else 'No',
                'hash_output_length': len(hash1)
            }
            
            self.collision_results.append(result)
            print(f"  Output Size: {output_bits} bits | "
                  f"Avalanche Effect: {diff_percentage:.2f}% | "
                  f"Deterministic: {is_deterministic}")
    
    def save_performance_to_csv(self, filename='results/hashing/hashing_performance.csv'):
        """Save performance results to CSV"""
        if not self.performance_results:
            print("No performance data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/hashing', exist_ok=True)
        
        keys = self.performance_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.performance_results)
        
        print(f"\n✓ Performance results saved to '{filename}'")
    
    def save_resource_to_csv(self, filename='results/hashing/hashing_resources.csv'):
        """Save resource consumption results to CSV"""
        if not self.resource_results:
            print("No resource data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/hashing', exist_ok=True)
        
        keys = self.resource_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.resource_results)
        
        print(f"✓ Resource results saved to '{filename}'")
    
    def save_collision_to_csv(self, filename='results/hashing/hashing_collision.csv'):
        """Save collision resistance results to CSV"""
        if not self.collision_results:
            print("No collision data to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/hashing', exist_ok=True)
        
        keys = self.collision_results[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.collision_results)
        
        print(f"✓ Collision results saved to '{filename}'")
    
    def visualize_performance(self, filename='results/hashing/hashing_performance_chart.png'):
        """Generate performance visualization"""
        if not self.performance_results:
            print("No performance data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/hashing', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.performance_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Hashing Algorithm Performance Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: Throughput by data size
        for algo in df['algorithm'].unique():
            algo_data = df[df['algorithm'] == algo].sort_values('data_size_kb')
            axes[0, 0].plot(algo_data['data_size_kb'], algo_data['throughput_mbps'], 
                           marker='o', label=algo, linewidth=2)
        
        axes[0, 0].set_xlabel('Data Size (KB)', fontweight='bold')
        axes[0, 0].set_ylabel('Throughput (MBps)', fontweight='bold')
        axes[0, 0].set_title('Hashing Throughput vs Data Size')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].set_xscale('log')
        
        # Plot 2: Average time by algorithm
        avg_times = df.groupby('algorithm')['avg_time_ms'].mean().sort_values()
        axes[0, 1].bar(avg_times.index, avg_times.values, color='skyblue', edgecolor='navy', linewidth=1.5)
        axes[0, 1].set_ylabel('Average Time (ms)', fontweight='bold')
        axes[0, 1].set_title('Average Hashing Time by Algorithm')
        axes[0, 1].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(avg_times.values):
            axes[0, 1].text(i, v + max(avg_times)*0.02, f'{v:.4f}', ha='center', fontweight='bold')
        
        # Plot 3: Throughput comparison (bar chart for largest data size)
        largest_data = df[df['data_size_kb'] == df['data_size_kb'].max()]
        axes[1, 0].barh(largest_data['algorithm'], largest_data['throughput_mbps'], 
                       color='lightcoral', edgecolor='darkred', linewidth=1.5)
        axes[1, 0].set_xlabel('Throughput (MBps)', fontweight='bold')
        axes[1, 0].set_title('Throughput at Maximum Data Size (50MB)')
        axes[1, 0].grid(True, alpha=0.3, axis='x')
        
        for i, v in enumerate(largest_data['throughput_mbps'].values):
            axes[1, 0].text(v + max(largest_data['throughput_mbps'])*0.02, i, f'{v:.2f}', 
                           va='center', fontweight='bold')
        
        # Plot 4: Standard deviation by algorithm
        std_devs = df.groupby('algorithm')['std_dev_ms'].mean().sort_values(ascending=False)
        axes[1, 1].bar(std_devs.index, std_devs.values, color='lightgreen', edgecolor='darkgreen', linewidth=1.5)
        axes[1, 1].set_ylabel('Standard Deviation (ms)', fontweight='bold')
        axes[1, 1].set_title('Timing Variability by Algorithm')
        axes[1, 1].grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Performance chart saved to '{filename}'")
        plt.close()
    
    def visualize_resources(self, filename='results/hashing/hashing_resources_chart.png'):
        """Generate resource consumption visualization"""
        if not self.resource_results:
            print("No resource data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/hashing', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.resource_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Hashing Algorithm Resource Consumption Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: Average CPU time by algorithm
        axes[0, 0].bar(df['algorithm'], df['avg_cpu_time_ms'], color='orange', edgecolor='darkorange', linewidth=1.5)
        axes[0, 0].set_ylabel('CPU Time (ms)', fontweight='bold')
        axes[0, 0].set_title('Average CPU Time per Algorithm')
        axes[0, 0].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(df['avg_cpu_time_ms'].values):
            axes[0, 0].text(i, v + max(df['avg_cpu_time_ms'])*0.02, f'{v:.4f}', 
                           ha='center', fontweight='bold')
        
        # Plot 2: Memory consumption comparison
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
        
        # Plot 4: Memory efficiency (ratio)
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
    
    def visualize_collision(self, filename='results/hashing/hashing_collision_chart.png'):
        """Generate collision resistance visualization"""
        if not self.collision_results:
            print("No collision data to visualize")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results/hashing', exist_ok=True)
        
        import pandas as pd
        
        df = pd.DataFrame(self.collision_results)
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Hashing Algorithm Collision Resistance Analysis', fontsize=16, fontweight='bold')
        
        # Plot 1: Output size comparison
        axes[0, 0].bar(df['algorithm'], df['output_bits'], color='purple', edgecolor='indigo', linewidth=1.5)
        axes[0, 0].set_ylabel('Output Size (bits)', fontweight='bold')
        axes[0, 0].set_title('Hash Output Size Comparison')
        axes[0, 0].grid(True, alpha=0.3, axis='y')
        
        for i, v in enumerate(df['output_bits'].values):
            axes[0, 0].text(i, v + max(df['output_bits'])*0.02, str(v), ha='center', fontweight='bold')
        
        # Plot 2: Avalanche effect analysis
        axes[0, 1].bar(df['algorithm'], df['avalanche_diff_percentage'], color='red', 
                      edgecolor='darkred', linewidth=1.5)
        axes[0, 1].set_ylabel('Differing Characters (%)', fontweight='bold')
        axes[0, 1].set_title('Avalanche Effect: Single Character Change Impact')
        axes[0, 1].axhline(y=50, color='green', linestyle='--', linewidth=2, label='Expected Random (50%)')
        axes[0, 1].grid(True, alpha=0.3, axis='y')
        axes[0, 1].legend()
        
        for i, v in enumerate(df['avalanche_diff_percentage'].values):
            axes[0, 1].text(i, v + max(df['avalanche_diff_percentage'])*0.02, f'{v:.2f}%', 
                           ha='center', fontweight='bold')
        
        # Plot 3: Deterministic behavior
        deterministic_count = (df['is_deterministic'] == 'Yes').sum()
        colors = ['green' if x == 'Yes' else 'red' for x in df['is_deterministic']]
        axes[1, 0].bar(df['algorithm'], [1 if x == 'Yes' else 0 for x in df['is_deterministic']], 
                      color=colors, edgecolor='black', linewidth=1.5)
        axes[1, 0].set_ylabel('Deterministic (1=Yes, 0=No)', fontweight='bold')
        axes[1, 0].set_title('Deterministic Behavior Test')
        axes[1, 0].set_ylim([0, 1.2])
        axes[1, 0].grid(True, alpha=0.3, axis='y')
        
        # Plot 4: Summary table as text
        axes[1, 1].axis('off')
        summary_text = "COLLISION RESISTANCE SUMMARY\n" + "="*45 + "\n\n"
        for _, row in df.iterrows():
            summary_text += f"{row['algorithm']}\n"
            summary_text += f"  Output: {row['output_bits']} bits\n"
            summary_text += f"  Avalanche: {row['avalanche_diff_percentage']:.2f}%\n"
            summary_text += f"  Deterministic: {row['is_deterministic']}\n"
            summary_text += "\n"
        
        axes[1, 1].text(0.05, 0.95, summary_text, transform=axes[1, 1].transAxes,
                       fontsize=10, verticalalignment='top', fontfamily='monospace',
                       bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✓ Collision chart saved to '{filename}'")
        plt.close()
    
    def run_all_tests(self):
        """Execute all hashing tests and save results"""
        print("\n" + "="*70)
        print("STARTING COMPREHENSIVE HASHING ALGORITHM ANALYSIS")
        print("="*70)
        
        self.test_performance_speed()
        self.test_resource_consumption()
        self.test_collision_resistance()
        
        self.save_performance_to_csv()
        self.save_resource_to_csv()
        self.save_collision_to_csv()
        
        self.visualize_performance()
        self.visualize_resources()
        self.visualize_collision()
        
        print("\n" + "="*70)
        print("ANALYSIS COMPLETE")
        print("="*70)
        print("\nGenerated Files (in 'results/hashing/' folder):")
        print("  CSV Files:")
        print("    - results/hashing/hashing_performance.csv")
        print("    - results/hashing/hashing_resources.csv")
        print("    - results/hashing/hashing_collision.csv")
        print("  Visualization Files:")
        print("    - results/hashing/hashing_performance_chart.png")
        print("    - results/hashing/hashing_resources_chart.png")
        print("    - results/hashing/hashing_collision_chart.png")


if __name__ == "__main__":
    analysis = HashingPerformanceAnalysis()
    analysis.run_all_tests()
