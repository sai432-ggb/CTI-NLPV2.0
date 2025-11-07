import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification

print("🔍 Testing Intel Acceleration with scikit-learn")
print("=" * 60)

# Create large synthetic dataset
X, y = make_classification(n_samples=50000, n_features=50, random_state=42)
print(f"📊 Dataset: {X.shape[0]} samples, {X.shape[1]} features")

# Test WITHOUT Intel extension
print("\n🧠 1. Training with standard scikit-learn (CPU)...")
model_cpu = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
start = time.time()
model_cpu.fit(X, y)
cpu_time = time.time() - start
print(f"⏱ CPU Time: {cpu_time:.2f} seconds")

# Test WITH Intel extension (if available)
try:
    from sklearnex import patch_sklearn
    patch_sklearn()

    # Re-import model after patching
    from sklearn.ensemble import RandomForestClassifier

    print("\n⚡ 2. Training with Intel Extension (Optimized)...")
    model_opt = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    start = time.time()
    model_opt.fit(X, y)
    opt_time = time.time() - start
    print(f"⏱ Optimized Time: {opt_time:.2f} seconds")

    speedup = cpu_time / opt_time
    print(f"\n🚀 Speedup: {speedup:.2f}x faster")

    if speedup > 1.5:
        print("✅ Intel acceleration is working well!")
    else:
        print("ℹ️ Minimal speedup — CPU is sufficient for this task.")

except ImportError:
    print("\n⚠️ Intel Extension not installed.")
    print("   To enable acceleration, run:")
    print("   pip install scikit-learn-intelex")