import subprocess
import sys

scripts = [
    'src/hashing_analysis.py',
    'src/symmetric_analysis.py',
    'src/asymmetric_analysis.py'
]

for script in scripts:
    print("\n" + "="*70)
    print(f"Running {script}...")
    print("="*70)
    try:
        result = subprocess.run([sys.executable, script], check=True)
        print(f"✓ {script} completed successfully\n")
    except subprocess.CalledProcessError:
        print(f"✗ {script} failed to complete.\n")
        break

print("\n" + "="*70)
print("ALL TESTS COMPLETED (or stopped due to error)")
print("="*70)