import time
from response import ResponseEngine

r = ResponseEngine(dry_run=False)
try:
    print("Cutting network in 3 seconds...")
    time.sleep(3)
    r.kill_switch()
    print("Cut. Restoring in 10 seconds...")
    time.sleep(10)
finally:
    r.restore_network()
    print("Network restored.")