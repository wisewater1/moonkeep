import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'backend'))

try:
    from backend.plugins.spoofer import SpooferPlugin
    print("SpooferPlugin import OK")
except Exception as e:
    print(f"SpooferPlugin import FAILED: {e}")

try:
    from backend.plugins.wifi_strike import WiFiAttackPlugin
    print("WiFiAttackPlugin import OK")
except Exception as e:
    print(f"WiFiAttackPlugin import FAILED: {e}")
