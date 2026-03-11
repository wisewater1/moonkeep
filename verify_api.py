import requests
import time

url = "http://localhost:8000/plugins"
for i in range(5):
    try:
        resp = requests.get(url)
        plugins = resp.json()
        print(f"Attempt {i+1}: Found {len(plugins)} plugins: {[p['name'] for p in plugins]}")
    except Exception as e:
        print(f"Attempt {i+1}: Failed to connect: {e}")
    time.sleep(1)
