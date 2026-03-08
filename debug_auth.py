"""Quick debug script — prints fingerprint and raw Firebase response."""
import requests
from identity_module import get_hardware_fingerprint
from config import FIREBASE_PROJECT_ID, FIREBASE_COLLECTION, WHITELIST_ENDPOINT

hw = get_hardware_fingerprint()
fp = hw["fingerprint"]

print(f"Full fingerprint : {fp}")
print(f"Project ID       : {FIREBASE_PROJECT_ID}")
print(f"Collection       : {FIREBASE_COLLECTION}")

url = WHITELIST_ENDPOINT.format(
    project_id=FIREBASE_PROJECT_ID,
    collection=FIREBASE_COLLECTION,
    fingerprint=fp,
)
print(f"\nFirestore URL:\n  {url}\n")

try:
    r = requests.get(url, timeout=10)
    print(f"HTTP Status : {r.status_code}")
    print(f"Response    : {r.text[:500]}")
except Exception as e:
    print(f"Request failed: {e}")
