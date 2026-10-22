from datetime import datetime

from database.database import (
    initialize_database,
    get_connection,
    get_risks
)


class RiskEngine:
    """
    CloudGuard AI Risk Engine

    Responsibilities:
    - Analyze detected risks
    - Classify severity
    - Calculate security posture
    - Generate risk statistics
    """

    def __init__(self):
        initialize_database()

    # =========================================================
    # 1. SEVERITY CLASSIFICATION
    # =========================================================

    def classify_severity(self, risk_score):
        if risk_score >= 90:
            return "Critical"

        elif risk_score >= 75:
            return "High"

        elif risk_score >= 50:
            return "Medium"

        else:
            return "Low"

    # =========================================================
    # 2. RISK LEVEL
    # =========================================================

    def get_risk_level(self, risk_score):
        if risk_score >= 90:
            return "CRITICAL"

        elif risk_score >= 75:
            return "HIGH"

        elif risk_score >= 50:
            return "MEDIUM"

        else:
            return "LOW"

    # =========================================================
    # 3. GET COLUMN VALUE SAFELY
    # =========================================================

    def get_value(self, risk, possible_names, default=""):
        """
        Get a value from SQLite Row using multiple possible
        column names.

        This makes the Risk Engine compatible with the
        existing CloudGuard database structure.
        """

        for name in possible_names:

            try:
                value = risk[name]

                if value is not None:
                    return value

            except (KeyError, IndexError):
                continue

        return default

    # =========================================================
    # 4. ANALYZE ALL RISKS
    # =========================================================

    def analyze_risks(self):

        risks = get_risks()

        analyzed_risks = []

        for risk in risks:

            # Get risk score safely
            score_value = self.get_value(
                risk,
                [
                    "risk_score",
                    "score",
                    "riskScore"
                ],
                0
            )

            try:
                risk_score = float(score_value)

            except (TypeError, ValueError):
                risk_score = 0

            # Get other database values safely
            risk_id = self.get_value(
                risk,
                [
                    "risk_id",
                    "id",
                    "riskId"
                ],
                "N/A"
            )

            resource_id = self.get_value(
                risk,
                [
                    "resource_id",
                    "resource",
                    "resourceId"
                ],
                "N/A"
            )

            # Existing database may use different names
            risk_name = self.get_value(
                risk,
                [
                    "risk_name",
                    "risk_type",
                    "finding",
                    "title",
                    "name",
                    "issue"
                ],
                "Security Risk"
            )

            status = self.get_value(
                risk,
                [
                    "status",
                    "risk_status"
                ],
                "Open"
            )

            # Calculate severity ourselves
            severity = self.classify_severity(
                risk_score
            )

            risk_level = self.get_risk_level(
                risk_score
            )

            analyzed_risks.append(
                {
                    "risk_id": risk_id,
                    "resource_id": resource_id,
                    "risk_name": risk_name,
                    "risk_score": risk_score,
                    "severity": severity,
                    "risk_level": risk_level,
                    "status": status
                }
            )

        return analyzed_risks

    # =========================================================
    # 5. RISK SUMMARY
    # =========================================================

    def get_risk_summary(self):

        risks = self.analyze_risks()

        summary = {
            "total": len(risks),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "average_score": 0
        }

        if not risks:
            return summary

        total_score = 0

        for risk in risks:

            score = risk["risk_score"]

            total_score += score

            severity = risk["severity"].lower()

            if severity == "critical":
                summary["critical"] += 1

            elif severity == "high":
                summary["high"] += 1

            elif severity == "medium":
                summary["medium"] += 1

            elif severity == "low":
                summary["low"] += 1

        summary["average_score"] = round(
            total_score / len(risks),
            2
        )

        return summary

    # =========================================================
    # 6. SECURITY POSTURE SCORE
    # =========================================================

    def calculate_security_posture(self):

        risks = self.analyze_risks()

        if not risks:
            return 100

        total_penalty = 0

        for risk in risks:

            score = risk["risk_score"]

            if score >= 90:
                penalty = 8

            elif score >= 75:
                penalty = 5

            elif score >= 50:
                penalty = 3

            else:
                penalty = 1

            total_penalty += penalty

        posture_score = 100 - total_penalty

        posture_score = max(
            0,
            min(100, posture_score)
        )

        return posture_score

    # =========================================================
    # 7. POSTURE STATUS
    # =========================================================

    def get_posture_status(self, posture_score):

        if posture_score >= 90:
            return "Excellent"

        elif posture_score >= 75:
            return "Good"

        elif posture_score >= 60:
            return "Needs Improvement"

        else:
            return "Critical"

    # =========================================================
    # 8. SAVE SECURITY POSTURE
    # =========================================================

    def save_security_posture(self):

        posture_score = self.calculate_security_posture()

        posture_status = self.get_posture_status(
            posture_score
        )

        connection = get_connection()
        cursor = connection.cursor()

        # Check available columns first
        cursor.execute(
            "PRAGMA table_info(security_posture)"
        )

        columns = [
            row[1]
            for row in cursor.fetchall()
        ]

        # Build insert according to existing database
        if (
            "posture_score" in columns
            and "posture_status" in columns
            and "created_at" in columns
        ):

            cursor.execute(
                """
                INSERT INTO security_posture
                (
                    posture_score,
                    posture_status,
                    created_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    posture_score,
                    posture_status,
                    datetime.now().isoformat()
                )
            )

        elif (
            "score" in columns
            and "status" in columns
        ):

            cursor.execute(
                """
                INSERT INTO security_posture
                (
                    score,
                    status
                )
                VALUES (?, ?)
                """,
                (
                    posture_score,
                    posture_status
                )
            )

        connection.commit()
        connection.close()

        return {
            "score": posture_score,
            "status": posture_status
        }

    # =========================================================
    # 9. COMPLETE RISK ANALYSIS
    # =========================================================

    def run_analysis(self):

        analyzed_risks = self.analyze_risks()

        summary = self.get_risk_summary()

        posture_score = self.calculate_security_posture()

        posture_status = self.get_posture_status(
            posture_score
        )

        return {
            "risks": analyzed_risks,
            "summary": summary,
            "posture_score": posture_score,
            "posture_status": posture_status
        }


# =============================================================
# TEST RISK ENGINE
# =============================================================

if __name__ == "__main__":

    print()
    print("=" * 45)
    print("CloudGuard AI Risk Engine")
    print("=" * 45)

    engine = RiskEngine()

    result = engine.run_analysis()

    summary = result["summary"]

    print()
    print("Risk Analysis Completed")
    print("-" * 45)

    print(f"Total Risks : {summary['total']}")
    print(f"Critical    : {summary['critical']}")
    print(f"High        : {summary['high']}")
    print(f"Medium      : {summary['medium']}")
    print(f"Low         : {summary['low']}")
    print(
        f"Average Risk Score : "
        f"{summary['average_score']}"
    )

    print()
    print("-" * 45)

    print(
        f"Security Posture : "
        f"{result['posture_score']}/100"
    )

    print(
        f"Posture Status   : "
        f"{result['posture_status']}"
    )

    print()
    print("=" * 45)