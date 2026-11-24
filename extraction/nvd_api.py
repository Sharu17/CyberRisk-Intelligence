
import requests
import json
from pathlib import Path

# NVD API endpoint
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Request vulnerability data
response = requests.get(API_URL, timeout=30)

# Check whether the request was successful
response.raise_for_status()

# Convert JSON response into Python dictionary
data = response.json()

# Extract vulnerability records
vulnerabilities = data.get("vulnerabilities", [])

print("Total records retrieved:", len(vulnerabilities))

# Save raw response
output_path = Path("data/raw/nvd_raw.json")

with output_path.open("w", encoding="utf-8") as file:
    json.dump(data, file, indent=4)

print("Raw data saved successfully!")