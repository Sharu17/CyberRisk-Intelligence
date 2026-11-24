
import requests
import json
import time

from datetime import datetime, timedelta, timezone
from pathlib import Path


# Project configuration
PROJECT_DIR = Path(__file__).resolve().parent.parent

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

OUTPUT_FILE = PROJECT_DIR / "data" / "raw" / "nvd_raw.json"

RESULTS_PER_PAGE = 2000


def fetch_vulnerabilities():

    # Define the date range: last 30 days
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=30)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": 0
    }

    all_vulnerabilities = []
    total_results = None

    session = requests.Session()

    print("Starting NVD data extraction...")

    while total_results is None or params["startIndex"] < total_results:

        print(f"Fetching records from index {params['startIndex']}...")

        try:
            response = session.get(
                API_URL,
                params=params,
                timeout=60
            )

            if response.status_code == 429:
                print("Rate limit reached. Waiting 30 seconds...")
                time.sleep(30)
                continue

            response.raise_for_status()

            data = response.json()

        except requests.RequestException as error:
            raise RuntimeError(
                f"NVD API request failed: {error}"
            ) from error

        except ValueError as error:
            raise RuntimeError(
                "The API returned invalid JSON."
            ) from error

        # Get total number of matching records
        if total_results is None:
            total_results = data.get("totalResults", 0)

            print("Total matching records:", total_results)

        batch = data.get("vulnerabilities", [])

        if not batch:
            break

        all_vulnerabilities.extend(batch)

        params["startIndex"] += len(batch)

        print("Records collected:", len(all_vulnerabilities))

        # Conservative delay for unauthenticated API access
        if params["startIndex"] < total_results:
            time.sleep(6.5)

    session.close()

    # Build the final dataset
    result = {
        "totalResults": total_results,
        "retrievedRecords": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities
    }

    # Save only after successful extraction
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print("\nExtraction completed!")
    print("Total records collected:", len(all_vulnerabilities))
    print("Saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    fetch_vulnerabilities()