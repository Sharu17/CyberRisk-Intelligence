
import requests
import json
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

API_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

OUTPUT_FILE = PROJECT_DIR / "data" / "raw" / "cisa_kev.json"


def fetch_cisa_kev():

    print("Starting CISA KEV extraction...")

    response = requests.get(API_URL, timeout=30)
    response.raise_for_status()

    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    expected_count = data.get("count")

    if not isinstance(vulnerabilities, list):
        raise ValueError("Invalid CISA vulnerability data.")

    if expected_count != len(vulnerabilities):
        raise ValueError("CISA record count does not match catalogue.")

    if any(not item.get("cveID") for item in vulnerabilities):
        raise ValueError("One or more records are missing CVE IDs.")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    print("\nCISA extraction completed!")
    print("---------------------------")
    print("Catalog version:", data.get("catalogVersion"))
    print("Total vulnerabilities:", len(vulnerabilities))
    print("Saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    fetch_cisa_kev()
