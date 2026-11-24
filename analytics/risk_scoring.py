
import pandas as pd
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_DIR / "data" / "processed" /
    "enriched_vulnerabilities.csv"
)

OUTPUT_FILE = (
    PROJECT_DIR / "data" / "processed" /
    "risk_prioritised_vulnerabilities.csv"
)


def assign_risk_priority(row):

    score = row["cvss_score"]
    is_kev = row["is_kev"]

    if is_kev and pd.isna(score):
        return "HIGH"

    if pd.isna(score):
        return "UNCLASSIFIED"

    if is_kev and score >= 9:
        return "CRITICAL"

    if is_kev:
        return "HIGH"

    if score >= 9:
        return "HIGH"

    if score >= 7:
        return "MEDIUM"

    return "LOW"


def generate_risk_scores():

    print("Starting risk prioritisation...")

    df = pd.read_csv(INPUT_FILE)

    df["is_kev"] = (
        df["is_kev"].astype(str).str.lower() == "true"
    )

    df["cvss_score"] = pd.to_numeric(
        df["cvss_score"], errors="coerce"
    )

    df["risk_priority"] = df.apply(
        assign_risk_priority, axis=1
    )

    df.to_csv(OUTPUT_FILE, index=False)

    print("\nRISK PRIORITISATION RESULTS")
    print("---------------------------")

    print("\nRisk distribution:")
    print(df["risk_priority"].value_counts())

    print("\nKEV risk distribution:")
    print(
        df[df["is_kev"]]["risk_priority"].value_counts()
    )

    print("\nSaved prioritised dataset:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    generate_risk_scores()
