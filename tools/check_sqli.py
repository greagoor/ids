import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors import sqli
import inspect

print("detect signature:", inspect.signature(sqli.detect))

# Test the actual SQLi payload from Part C Input 2
payloads = [
    "http://localhost/login?user=admin'--&pass=x",
    "admin'--",
    "' OR 1=1--",
    "http://localhost/index.html",
]

for p in payloads:
    result = sqli.detect(p)
    print(f"  detect({p[:60]!r}) -> {result}")
