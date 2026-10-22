import sqlite3
from datetime import datetime
from pathlib import Path


# ============================================================
# CLOUDGUARD AI - AI RECOMMENDATION ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "cloudguard.db"


class AIRecommendationEngine:

    def __init__(self):
        self.db_path = DB_PATH

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    # ========================================================
    # GET RISKS
    # ========================================================

    def get_risks(self):

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM risks")

        rows = cursor.fetchall()

        columns = [
            description[0]
            for description in cursor.description
        ]

        connection.close()

        return [
            dict(zip(columns, row))
            for row in rows
        ]

    # ========================================================
    # GET VALUE
    # ========================================================

    def get_value(self, risk, names):

        for name in names:

            if name in risk and risk[name] is not None:
                return risk[name]

        return ""

    # ========================================================
    # AI RECOMMENDATION
    # ========================================================

    def generate_recommendation(self, risk_name):

        risk = str(risk_name).lower()

        if "public storage" in risk:

            return {
                "recommendation":
                    "Disable public access to the storage bucket and enable private access controls.",
                "priority":
                    "Critical",
                "action":
                    "Block public access and review bucket permissions.",
                "impact":
                    "Reduces the possibility of unauthorized data exposure."
            }

        if "encryption" in risk:

            return {
                "recommendation":
                    "Enable encryption for stored data and use managed encryption keys where possible.",
                "priority":
                    "High",
                "action":
                    "Enable encryption and verify encryption configuration.",
                "impact":
                    "Protects sensitive information from unauthorized disclosure."
            }

        if "publicly exposed virtual machine" in risk:

            return {
                "recommendation":
                    "Remove unnecessary public exposure and restrict access using trusted network ranges.",
                "priority":
                    "High",
                "action":
                    "Restrict inbound traffic and use private networking.",
                "impact":
                    "Reduces attack surface and unauthorized remote access."
            }

        if "open management port" in risk:

            return {
                "recommendation":
                    "Close unnecessary management ports and allow administrative access only from trusted sources.",
                "priority":
                    "Critical",
                "action":
                    "Restrict management ports using firewall or security-group rules.",
                "impact":
                    "Reduces remote attack opportunities."
            }

        if "iam permissions" in risk:

            return {
                "recommendation":
                    "Apply the principle of least privilege and remove unnecessary IAM permissions.",
                "priority":
                    "Critical",
                "action":
                    "Review roles and remove excessive permissions.",
                "impact":
                    "Limits the damage caused by compromised accounts."
            }

        if "mfa" in risk:

            return {
                "recommendation":
                    "Enable Multi-Factor Authentication for privileged and sensitive accounts.",
                "priority":
                    "High",
                "action":
                    "Enable MFA and verify administrator accounts.",
                "impact":
                    "Provides an additional authentication layer."
            }

        if "password" in risk:

            return {
                "recommendation":
                    "Enforce a strong password policy with minimum length and complexity requirements.",
                "priority":
                    "High",
                "action":
                    "Update password policy and enforce secure authentication rules.",
                "impact":
                    "Reduces password-based attacks."
            }

        if "access review" in risk:

            return {
                "recommendation":
                    "Perform periodic access reviews and remove inactive or unnecessary accounts.",
                "priority":
                    "Medium",
                "action":
                    "Review user and role permissions regularly.",
                "impact":
                    "Prevents unnecessary access from remaining active."
            }

        if "logging" in risk:

            return {
                "recommendation":
                    "Enable centralized security logging and continuous monitoring.",
                "priority":
                    "Medium",
                "action":
                    "Enable audit logs and monitor security events.",
                "impact":
                    "Improves incident detection and investigation."
            }

        if "monitoring" in risk:

            return {
                "recommendation":
                    "Enable continuous monitoring and security telemetry for the affected resource.",
                "priority":
                    "Medium",
                "action":
                    "Enable monitoring and configure security alerts.",
                "impact":
                    "Improves visibility into abnormal activity."
            }

        return {
            "recommendation":
                "Review the resource configuration and apply appropriate security controls.",
            "priority":
                "Medium",
            "action":
                "Perform a detailed security configuration review.",
            "impact":
                "Improves the overall cloud security posture."
        }

    # ========================================================
    # DISPLAY RECOMMENDATIONS
    # ========================================================

    def run(self):

        print("=" * 65)
        print("CloudGuard AI - AI Recommendation Engine")
        print("=" * 65)

        risks = self.get_risks()

        print(
            f"Security Risks Analysed : {len(risks)}"
        )

        if not risks:

            print("No security risks found.")
            return

        print()

        critical = 0
        high = 0
        medium = 0

        for index, risk in enumerate(risks, start=1):

            risk_name = self.get_value(
                risk,
                [
                    "risk_type",
                    "risk_name",
                    "title",
                    "name"
                ]
            )

            resource = self.get_value(
                risk,
                [
                    "resource_name",
                    "resource",
                    "asset_name"
                ]
            )

            severity = self.get_value(
                risk,
                [
                    "severity",
                    "risk_level",
                    "level"
                ]
            )

            recommendation = self.generate_recommendation(
                risk_name
            )

            priority = recommendation["priority"]

            if priority == "Critical":
                critical += 1

            elif priority == "High":
                high += 1

            else:
                medium += 1

            print("-" * 65)

            print(
                f"Risk #{index}        : {risk_name}"
            )

            print(
                f"Resource            : {resource}"
            )

            print(
                f"Detected Severity   : {severity}"
            )

            print(
                f"AI Priority         : {priority}"
            )

            print(
                f"Recommendation      : "
                f"{recommendation['recommendation']}"
            )

            print(
                f"Recommended Action  : "
                f"{recommendation['action']}"
            )

            print(
                f"Expected Impact     : "
                f"{recommendation['impact']}"
            )

        print()
        print("=" * 65)
        print("AI RECOMMENDATION SUMMARY")
        print("=" * 65)

        print(
            f"Total Risks         : {len(risks)}"
        )

        print(
            f"Critical Priority   : {critical}"
        )

        print(
            f"High Priority       : {high}"
        )

        print(
            f"Medium Priority     : {medium}"
        )

        print(
            "AI Recommendation   : Generated"
        )

        print(
            "Remediation Ready   : Yes"
        )

        print("=" * 65)

        return True


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    engine = AIRecommendationEngine()

    engine.run()

    print()
    print(
        "AI recommendation analysis completed successfully."
    )