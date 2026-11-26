
import pandas as pd
from pathlib import Path

from sqlalchemy import MetaData, Table
from sqlalchemy.dialects.postgresql import insert as pg_insert

from database.db_connection import engine


PROJECT_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_DIR
    / "data"
    / "processed"
    / "risk_prioritised_vulnerabilities.csv"
)

BATCH_SIZE = 500


def load_vulnerabilities():

    print("Starting database loading...")

    # Step 1: Read processed CSV
    df = pd.read_csv(INPUT_FILE)

    # Step 2: Rename columns to match PostgreSQL
    df.rename(columns={
        "vendorProject": "vendor_project",
        "vulnerabilityName": "vulnerability_name",
        "dateAdded": "date_added",
        "requiredAction": "required_action",
        "dueDate": "due_date",
        "knownRansomwareCampaignUse":
            "known_ransomware_campaign_use"
    }, inplace=True)

    # Step 3: Convert date columns
    date_columns = [
        "published_date",
        "last_modified",
        "date_added",
        "due_date"
    ]

    for column in date_columns:
        df[column] = pd.to_datetime(
            df[column],
            errors="coerce",
            utc=True
        )

    # PostgreSQL DATE columns need date values
    df["date_added"] = df["date_added"].dt.date
    df["due_date"] = df["due_date"].dt.date

    # Step 4: Replace pandas missing values with Python None
    df = df.astype(object).where(
        pd.notna(df),
        None
    )

    # Step 5: Convert DataFrame to records
    records = df.to_dict(orient="records")

    # Step 6: Reflect the existing PostgreSQL table
    metadata = MetaData()

    vulnerabilities = Table(
        "vulnerabilities",
        metadata,
        autoload_with=engine
    )

    # Step 7: Prepare PostgreSQL UPSERT
    insert_statement = pg_insert(vulnerabilities)

    update_columns = {
        column.name: getattr(
            insert_statement.excluded,
            column.name
        )
        for column in vulnerabilities.columns
        if column.name != "cve_id"
    }

    upsert_statement = insert_statement.on_conflict_do_update(
        index_elements=["cve_id"],
        set_=update_columns
    )

    # Step 8: Load records in batches
    with engine.begin() as connection:

        for start in range(0, len(records), BATCH_SIZE):

            batch = records[start:start + BATCH_SIZE]

            connection.execute(
                upsert_statement,
                batch
            )

            print(
                f"Processed {min(start + BATCH_SIZE, len(records))}"
                f"/{len(records)} records"
            )

    print("\nDatabase loading completed successfully!")
    print("Records processed:", len(records))


if __name__ == "__main__":
    load_vulnerabilities()
