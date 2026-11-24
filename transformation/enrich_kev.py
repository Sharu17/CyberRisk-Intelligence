
import json
import pandas as pd
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

NVD_FILE = PROJECT_DIR / "data" / "processed" / "vulnerabilities_clean.csv"
CISA_FILE = PROJECT_DIR / "data" / "raw" / "cisa_kev.json"

OUTPUT_FILE = (
    PROJECT_DIR / "data" / "processed" / "enriched_vulnerabilities.csv"
)


def enrich_with_kev():

    print("Starting NVD and CISA data enrichment...")

    # Load NVD dataset
    nvd_df = pd.read_csv(NVD_FILE)

    # Load CISA KEV dataset
    with CISA_FILE.open("r", encoding="utf-8") as file:
        cisa_data = json.load(file)

    kev_records = cisa_data.get("vulnerabilities", [])
    kev_df = pd.DataFrame(kev_records)

    # Select useful CISA fields
    kev_df = kev_df[[
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse"
    ]].copy()

    # Remove duplicate CVE IDs from CISA data
    kev_df = kev_df.drop_duplicates(subset=["cveID"])

    # Rename CISA CVE ID to match NVD column
    kev_df = kev_df.rename(columns={"cveID": "cve_id"})

    # Match NVD records with CISA KEV records
    enriched_df = nvd_df.merge(
        kev_df,
        on="cve_id",
        how="left",
        indicator=True,
        validate="one_to_one"
    )

    # Identify known exploited vulnerabilities
    enriched_df["is_kev"] = enriched_df["_merge"] == "both"

    # Remove temporary merge column
    enriched_df = enriched_df.drop(columns=["_merge"])

    # Save enriched dataset
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    enriched_df.to_csv(OUTPUT_FILE, index=False)

    # Display results
    total_nvd = len(nvd_df)
    total_kev = len(kev_df)
    matched_kev = int(enriched_df["is_kev"].sum())

    print("\nENRICHMENT RESULTS")
    print("------------------------")
    print("NVD records:", total_nvd)
    print("CISA KEV records:", total_kev)
    print("NVD records matched with KEV:", matched_kev)
    print("NVD records not found in KEV:", total_nvd - matched_kev)

    print("\nEnriched dataset saved at:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    enrich_with_kev()
