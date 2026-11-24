
from extraction.nvd_api import fetch_vulnerabilities
from transformation.cleaning import transform_data


def run_pipeline():

    print("\n==============================")
    print("CYBERRISK INTELLIGENCE")
    print("Starting automated pipeline")
    print("==============================\n")

    try:

        # Step 1: Extract data
        print("STEP 1: DATA EXTRACTION")
        fetch_vulnerabilities()

        # Step 2: Transform data
        print("\nSTEP 2: DATA TRANSFORMATION")
        transform_data()

        print("\n==============================")
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("==============================")

    except Exception as error:

        print("\nPIPELINE FAILED!")
        print("Error:", error)

        raise


if __name__ == "__main__":
    run_pipeline()