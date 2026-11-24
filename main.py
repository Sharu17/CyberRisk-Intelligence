
from extraction.nvd_api import fetch_vulnerabilities
from extraction.cisa_kev import fetch_cisa_kev

from transformation.cleaning import transform_data
from transformation.enrich_kev import enrich_with_kev

from analytics.risk_scoring import generate_risk_scores


def run_pipeline():

    print("\n================================")
    print("       CYBERRISK INTELLIGENCE")
    print("       AUTOMATED DATA PIPELINE")
    print("================================\n")

    try:

        # Step 1: Extract NVD data
        print("\nSTEP 1: NVD DATA EXTRACTION")
        fetch_vulnerabilities()

        # Step 2: Extract CISA KEV data
        print("\nSTEP 2: CISA KEV EXTRACTION")
        fetch_cisa_kev()

        # Step 3: Clean and validate NVD data
        print("\nSTEP 3: DATA CLEANING AND VALIDATION")
        transform_data()

        # Step 4: Enrich NVD data with CISA KEV
        print("\nSTEP 4: KEV DATA ENRICHMENT")
        enrich_with_kev()

        # Step 5: Calculate risk priorities
        print("\nSTEP 5: RISK PRIORITISATION")
        generate_risk_scores()

        print("\n================================")
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("================================")

    except Exception as error:

        print("\nPIPELINE FAILED!")
        print("Error:", error)

        raise


if __name__ == "__main__":
    run_pipeline()
