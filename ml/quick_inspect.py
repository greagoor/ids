# quick_inspect.py
import pandas as pd

df = pd.read_csv("C:\\csPR\\maliciousUrl.csv")
benign = df[df["type"] == "benign"]

print("=== BENIGN URL SAMPLES ===")
print(benign["url"].head(20).to_string())
print(f"\nBenign url_len mean: {benign['url_len'].mean():.1f}")
print(f"Malicious url_len mean: {df[df['type']!='benign']['url_len'].mean():.1f}")
print(f"\nBenign enh_long_path mean: {benign['enh_long_path'].mean():.3f}")
print(f"Malicious enh_long_path mean: {df[df['type']!='benign']['enh_long_path'].mean():.3f}")
print(f"\nBenign enh_subdomain_count mean: {benign['enh_subdomain_count'].mean():.3f}")
print(f"Malicious enh_subdomain_count mean: {df[df['type']!='benign']['enh_subdomain_count'].mean():.3f}")
print(f"\nBenign https mean: {benign['https'].mean():.3f}")
print(f"Malicious https mean: {df[df['type']!='benign']['https'].mean():.3f}")