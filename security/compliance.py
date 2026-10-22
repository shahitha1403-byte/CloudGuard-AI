import sqlite3
from datetime import datetime
from pathlib import Path


# ============================================================
# CLOUDGUARD AI - COMPLIANCE ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "cloudguard.db"


class ComplianceEngine:

    def __init__(self):
        self.db_path = DB_PATH

        self.controls = [
            {
                "framework": "CIS",
                "control_id": "CIS-01",
                "control_name": "Identity and Access Management",
                "description": "Ensure excessive permissions and unauthorized access are prevented.",
                "keywords": [
                    "Excessive IAM Permissions",
                    "MFA Not Enabled",
                    "Weak Password Policy"
                ]
            },
            {
                "framework": "CIS",
                "control_id": "CIS-04",
                "control_name": "Secure Configuration",
                "description": "Ensure cloud resources are securely configured.",
                "keywords": [
                    "Public Storage Bucket",
                    "Publicly Exposed Virtual Machine",
                    "Open Management Port"
                ]
            },
            {
                "framework": "CIS",
                "control_id": "CIS-06",
                "control_name": "Logging and Monitoring",
                "description": "Ensure security logging and monitoring are enabled.",
                "keywords": [
                    "Security Logging Disabled",
                    "VM Monitoring Disabled"
                ]
            },
            {
                "framework": "CIS",
                "control_id": "CIS-08",
                "control_name": "Data Protection",
                "description": "Ensure sensitive data is protected using encryption.",
                "keywords": [
                    "Encryption Disabled"
                ]
            },

            {
                "framework": "ISO 27001",
                "control_id": "ISO-A.8",
                "control_name": "Asset Management",
                "description": "Ensure information assets are identified and protected.",
                "keywords": [
                    "Public Storage Bucket",
                    "Encryption Disabled"
                ]
            },
            {
                "framework": "ISO 27001",
                "control_id": "ISO-A.9",
                "control_name": "Access Control",
                "description": "Ensure access to cloud resources follows least privilege.",
                "keywords": [
                    "Excessive IAM Permissions",
                    "MFA Not Enabled",
                    "Access Review Missing"
                ]
            },
            {
                "framework": "ISO 27001",
                "control_id": "ISO-A.12",
                "control_name": "Operations Security",
                "description": "Ensure monitoring, logging and secure configuration are maintained.",
                "keywords": [
                    "Security Logging Disabled",
                    "VM Monitoring Disabled",
                    "Open Management Port"
                ]
            },
            {
                "framework": "ISO 27001",
                "control_id": "ISO-A.13",
                "control_name": "Communications Security",
                "description": "Ensure network access is securely controlled.",
                "keywords": [
                    "Open Management Port",
                    "Publicly Exposed Virtual Machine"
                ]
            },

            {
                "framework": "GDPR",
                "control_id": "GDPR-32",
                "control_name": "Security of Processing",
                "description": "Ensure appropriate technical security measures are implemented.",
                "keywords": [
                    "Encryption Disabled",
                    "Public Storage Bucket",
                    "Excessive IAM Permissions"
                ]
            },
            {
                "framework": "GDPR",
                "control_id": "GDPR-33",
                "control_name": "Security Monitoring",
                "description": "Ensure security events are monitored and recorded.",
                "keywords": [
                    "Security Logging Disabled",
                    "VM Monitoring Disabled"
                ]
            },
            {
                "framework": "GDPR",
                "control_id": "GDPR-25",
                "control_name": "Data Protection by Design",
                "description": "Ensure security and privacy are considered in system configuration.",
                "keywords": [
                    "Public Storage Bucket",
                    "Encryption Disabled",
                    "Excessive IAM Permissions"
                ]
            }
        ]

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    # ========================================================
    # GET TABLE COLUMNS
    # ========================================================

    def get_columns(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute("PRAGMA table_info(compliance)")
        rows = cursor.fetchall()

        connection.close()

        return [row[1] for row in rows]

    # ========================================================
    # GET RISKS
    # ========================================================

    def get_risks(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM risks")

        rows = cursor.fetchall()

        column_names = [
            description[0]
            for description in cursor.description
        ]

        connection.close()

        risks = []

        for row in rows:
            risks.append(
                dict(zip(column_names, row))
            )

        return risks

    # ========================================================
    # FIND RISK MATCH
    # ========================================================

    def find_matching_risks(self, keywords, risks):

        matched = []

        for risk in risks:

            risk_text = " ".join(
                str(value)
                for value in risk.values()
                if value is not None
            ).lower()

            for keyword in keywords:

                if keyword.lower() in risk_text:

                    matched.append(risk)
                    break

        return matched

    # ========================================================
    # CHECK CONTROL
    # ========================================================

    def evaluate_control(self, control, risks):

        matched_risks = self.find_matching_risks(
            control["keywords"],
            risks
        )

        if len(matched_risks) == 0:

            status = "COMPLIANT"

            severity = "Low"

            score = 100

            explanation = (
                "No related security risks were detected. "
                "The control currently appears compliant."
            )

        else:

            critical_count = 0
            high_count = 0
            medium_count = 0

            for risk in matched_risks:

                risk_text = " ".join(
                    str(value)
                    for value in risk.values()
                    if value is not None
                ).lower()

                if "critical" in risk_text:
                    critical_count += 1

                elif "high" in risk_text:
                    high_count += 1

                elif "medium" in risk_text:
                    medium_count += 1

            if critical_count > 0:

                status = "NON-COMPLIANT"
                severity = "Critical"
                score = max(20, 100 - (critical_count * 25))

            elif high_count > 0:

                status = "PARTIALLY COMPLIANT"
                severity = "High"
                score = max(40, 100 - (high_count * 15))

            elif medium_count > 0:

                status = "PARTIALLY COMPLIANT"
                severity = "Medium"
                score = max(60, 100 - (medium_count * 10))

            else:

                status = "PARTIALLY COMPLIANT"
                severity = "Low"
                score = 75

            explanation = (
                f"{len(matched_risks)} related security risk(s) "
                f"were detected for this control."
            )

        return {
            "framework": control["framework"],
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "description": control["description"],
            "status": status,
            "severity": severity,
            "score": score,
            "matched_risks": matched_risks,
            "explanation": explanation
        }

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    def save_results(self, result):

        connection = self.get_connection()
        cursor = connection.cursor()

        columns = self.get_columns()

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        values_map = {

            "framework":
                result["framework"],

            "control_id":
                result["control_id"],

            "control_name":
                result["control_name"],

            "description":
                result["description"],

            "status":
                result["status"],

            "compliance_status":
                result["status"],

            "severity":
                result["severity"],

            "risk_level":
                result["severity"],

            "score":
                result["score"],

            "compliance_score":
                result["score"],

            "matched_risks":
                len(result["matched_risks"]),

            "risk_count":
                len(result["matched_risks"]),

            "explanation":
                result["explanation"],

            "remarks":
                result["explanation"],

            "checked_at":
                now,

            "created_at":
                now,

            "updated_at":
                now
        }

        insert_columns = []
        insert_values = []

        for column in columns:

            if column == "id":
                continue

            if column in values_map:

                insert_columns.append(column)
                insert_values.append(
                    values_map[column]
                )

        if not insert_columns:

            connection.close()

            raise Exception(
                "No compatible columns found in compliance table."
            )

        placeholders = ", ".join(
            ["?"] * len(insert_values)
        )

        query = f"""
            INSERT INTO compliance
            ({", ".join(insert_columns)})
            VALUES
            ({placeholders})
        """

        cursor.execute(
            query,
            insert_values
        )

        connection.commit()
        connection.close()

    # ========================================================
    # RUN COMPLIANCE ENGINE
    # ========================================================

    def run(self):

        print("=" * 60)
        print("CloudGuard AI - Compliance Engine")
        print("=" * 60)

        risks = self.get_risks()

        print(
            f"Security Risks Loaded : {len(risks)}"
        )

        total_controls = len(self.controls)

        compliant = 0
        partially_compliant = 0
        non_compliant = 0

        results = []

        for control in self.controls:

            result = self.evaluate_control(
                control,
                risks
            )

            self.save_results(result)

            results.append(result)

            if result["status"] == "COMPLIANT":
                compliant += 1

            elif result["status"] == "PARTIALLY COMPLIANT":
                partially_compliant += 1

            elif result["status"] == "NON-COMPLIANT":
                non_compliant += 1

            print(
                f'{control["framework"]} | '
                f'{control["control_id"]} | '
                f'{control["control_name"]} | '
                f'{result["status"]}'
            )

        print()
        print("=" * 60)
        print("COMPLIANCE SUMMARY")
        print("=" * 60)

        print(
            f"Total Controls        : {total_controls}"
        )

        print(
            f"Compliant Controls    : {compliant}"
        )

        print(
            f"Partially Compliant   : {partially_compliant}"
        )

        print(
            f"Non-Compliant        : {non_compliant}"
        )

        if total_controls > 0:

            overall_score = round(
                sum(
                    result["score"]
                    for result in results
                ) / total_controls,
                2
            )

        else:

            overall_score = 100

        print(
            f"Overall Compliance   : {overall_score}%"
        )

        print("=" * 60)

        return results


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    engine = ComplianceEngine()

    result = engine.run()

    print()
    print("Compliance analysis completed successfully.")