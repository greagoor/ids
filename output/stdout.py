import json

def emit(alert: dict):
    print(json.dumps(alert, indent=2))
