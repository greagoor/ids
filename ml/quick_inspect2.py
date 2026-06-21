# quick_inspect2.py
import pandas as pd

print("=== SQLi Dataset ===")
sqli = pd.read_csv("C:\\csPR\\sqli.csv")   # change filename
print(f"Shape: {sqli.shape}")
print(f"Columns: {sqli.columns.tolist()}")
print(f"Labels:\n{sqli['Label'].value_counts()}")
print(f"\nSample positives:")
print(sqli[sqli['Label']==1]['Sentence'].head(3).to_string())

print("\n=== XSS Dataset ===")
xss = pd.read_csv("C:\\csPR\\xss.csv")    # change filename
print(f"Shape: {xss.shape}")
print(f"Columns: {xss.columns.tolist()}")
print(f"Labels:\n{xss['Label'].value_counts()}")
print(f"\nSample positives:")
print(xss[xss['Label']==1]['Sentence'].head(3).to_string())