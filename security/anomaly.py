from datetime import datetime
import uuid

from database.database import (
    initialize_database,
    get_connection
)


class AnomalyDetector:
    """
    CloudGuard AI - Anomaly Detection Engine

    Detects unusual cloud activity using:
    - Failed login attempts
    - New source IPs
    - Data transfer spikes
    - Request volume spikes
    """

    def __init__(self):
        initialize_database()

    # =========================================================
    # 1. SIMULATED CLOUD ACTIVITY
    # =========================================================

    def generate_activity(self):

        return [
            {
                "resource_id": "RES-001",
                "activity": "Normal Storage Access",
                "requests": 120,
                "failed_logins": 2,
                "data_transfer_mb": 450,
                "new_ips": 1
            },
            {
                "resource_id": "RES-002",
                "activity": "High Network Activity",
                "requests": 980,
                "failed_logins": 8,
                "data_transfer_mb": 2100,
                "new_ips": 6
            },
            {
                "resource_id": "RES-003",
                "activity": "Multiple Failed Login Attempts",
                "requests": 320,
                "failed_logins": 35,
                "data_transfer_mb": 600,
                "new_ips": 12
            },
            {
                "resource_id": "RES-004",
                "activity": "Normal Database Activity",
                "requests": 210,
                "failed_logins": 1,
                "data_transfer_mb": 380,
                "new_ips": 1
            },
            {
                "resource_id": "RES-005",
                "activity": "Normal Network Activity",
                "requests": 180,
                "failed_logins": 2,
                "data_transfer_mb": 300,
                "new_ips": 2
            },
            {
                "resource_id": "RES-006",
                "activity": "Large Data Transfer",
                "requests": 450,
                "failed_logins": 4,
                "data_transfer_mb": 5200,
                "new_ips": 8
            }
        ]

    # =========================================================
    # 2. CALCULATE ANOMALY SCORE
    # =========================================================

    def calculate_anomaly_score(self, activity):

        score = 0

        # Failed login attempts
        if activity["failed_logins"] >= 30:
            score += 40

        elif activity["failed_logins"] >= 10:
            score += 25

        elif activity["failed_logins"] >= 5:
            score += 10

        # New IP addresses
        if activity["new_ips"] >= 10:
            score += 30

        elif activity["new_ips"] >= 5:
            score += 20

        elif activity["new_ips"] >= 3:
            score += 10

        # Data transfer
        if activity["data_transfer_mb"] >= 5000:
            score += 30

        elif activity["data_transfer_mb"] >= 2000:
            score += 20

        elif activity["data_transfer_mb"] >= 1000:
            score += 10

        # Request volume
        if activity["requests"] >= 1000:
            score += 20

        elif activity["requests"] >= 500:
            score += 10

        return min(score, 100)

    # =========================================================
    # 3. CLASSIFY ANOMALY
    # =========================================================

    def classify_anomaly(self, score):

        if score >= 80:
            return "Critical"

        elif score >= 60:
            return "High"

        elif score >= 30:
            return "Medium"

        return "Low"

    # =========================================================
    # 4. EXPLAIN ANOMALY
    # =========================================================

    def explain_anomaly(self, activity):

        reasons = []

        if activity["failed_logins"] >= 10:
            reasons.append(
                "Unusual number of failed login attempts"
            )

        if activity["new_ips"] >= 5:
            reasons.append(
                "Multiple new source IP addresses detected"
            )

        if activity["data_transfer_mb"] >= 2000:
            reasons.append(
                "Abnormally high data transfer detected"
            )

        if activity["requests"] >= 500:
            reasons.append(
                "Unusually high request volume detected"
            )

        if not reasons:
            return "No significant abnormal behavior detected."

        return "; ".join(reasons) + "."

    # =========================================================
    # 5. ANALYZE SINGLE ACTIVITY
    # =========================================================

    def analyze_activity(self, activity):

        score = self.calculate_anomaly_score(
            activity
        )

        severity = self.classify_anomaly(
            score
        )

        explanation = self.explain_anomaly(
            activity
        )

        if score >= 80:
            action = (
                "Immediate investigation and security "
                "response recommended."
            )

        elif score >= 60:
            action = (
                "Investigate the activity and monitor "
                "the affected resource closely."
            )

        elif score >= 30:
            action = (
                "Continue monitoring and review the activity."
            )

        else:
            action = (
                "Activity appears normal."
            )

        return {
            "resource_id": activity["resource_id"],
            "activity": activity["activity"],
            "anomaly_score": score,
            "severity": severity,
            "explanation": explanation,
            "recommended_action": action
        }

    # =========================================================
    # 6. RUN DETECTION
    # =========================================================

    def run_detection(self):

        activities = self.generate_activity()

        results = []

        for activity in activities:

            result = self.analyze_activity(
                activity
            )

            results.append(result)

        return results

    # =========================================================
    # 7. GET AUDIT COLUMN INFORMATION
    # =========================================================

    def get_audit_columns(self, cursor):

        cursor.execute(
            "PRAGMA table_info(audit_logs)"
        )

        return [
            row[1]
            for row in cursor.fetchall()
        ]

    # =========================================================
    # 8. SAVE ANOMALY AUDIT LOGS
    # =========================================================

    def save_anomaly_logs(self, results):

        connection = get_connection()
        cursor = connection.cursor()

        columns = self.get_audit_columns(
            cursor
        )

        for result in results:

            event_id = (
                "AUD-ANOM-"
                + uuid.uuid4().hex[:8].upper()
            )

            description = (
                f"Anomaly detected for "
                f"{result['resource_id']}: "
                f"{result['explanation']}"
            )

            created_at = datetime.now().isoformat()

            # -------------------------------------------------
            # Build INSERT dynamically according to the
            # existing audit_logs database structure.
            # -------------------------------------------------

            insert_columns = []
            values = []

            if "event_id" in columns:
                insert_columns.append("event_id")
                values.append(event_id)

            if "event_type" in columns:
                insert_columns.append("event_type")
                values.append("ANOMALY_DETECTION")

            if "description" in columns:
                insert_columns.append("description")
                values.append(description)

            if "severity" in columns:
                insert_columns.append("severity")
                values.append(result["severity"])

            if "created_at" in columns:
                insert_columns.append("created_at")
                values.append(created_at)

            # Additional common columns if present
            if "resource_id" in columns:
                insert_columns.append("resource_id")
                values.append(result["resource_id"])

            if "action" in columns:
                insert_columns.append("action")
                values.append("ANOMALY_DETECTED")

            if "status" in columns:
                insert_columns.append("status")
                values.append("OPEN")

            if "user" in columns:
                insert_columns.append("user")
                values.append("SYSTEM")

            if "username" in columns:
                insert_columns.append("username")
                values.append("SYSTEM")

            if insert_columns:

                placeholders = ", ".join(
                    ["?"] * len(insert_columns)
                )

                column_string = ", ".join(
                    insert_columns
                )

                query = f"""
                    INSERT INTO audit_logs
                    ({column_string})
                    VALUES ({placeholders})
                """

                cursor.execute(
                    query,
                    values
                )

        connection.commit()
        connection.close()

    # =========================================================
    # 9. COMPLETE PROCESS
    # =========================================================

    def run(self):

        results = self.run_detection()

        self.save_anomaly_logs(
            results
        )

        critical = 0
        high = 0
        medium = 0
        low = 0

        for result in results:

            severity = result["severity"]

            if severity == "Critical":
                critical += 1

            elif severity == "High":
                high += 1

            elif severity == "Medium":
                medium += 1

            else:
                low += 1

        return {
            "total": len(results),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "results": results
        }


# =============================================================
# TEST ANOMALY DETECTION
# =============================================================

if __name__ == "__main__":

    print()
    print("=" * 55)
    print("CloudGuard AI - Anomaly Detection Engine")
    print("=" * 55)

    detector = AnomalyDetector()

    result = detector.run()

    print()
    print("Anomaly Detection Completed")
    print("-" * 55)

    print(
        f"Total Activities Analyzed : "
        f"{result['total']}"
    )

    print(
        f"Critical Anomalies        : "
        f"{result['critical']}"
    )

    print(
        f"High Anomalies            : "
        f"{result['high']}"
    )

    print(
        f"Medium Anomalies          : "
        f"{result['medium']}"
    )

    print(
        f"Low / Normal              : "
        f"{result['low']}"
    )

    print()

    for index, item in enumerate(
        result["results"],
        start=1
    ):

        print(
            f"{index}. "
            f"{item['resource_id']} - "
            f"{item['activity']}"
        )

        print(
            f"   Anomaly Score : "
            f"{item['anomaly_score']}/100"
        )

        print(
            f"   Severity      : "
            f"{item['severity']}"
        )

        print(
            f"   Explanation   : "
            f"{item['explanation']}"
        )

        print(
            f"   Action        : "
            f"{item['recommended_action']}"
        )

        print("-" * 55)

    print()
    print(
        "Anomaly detection finished successfully."
    )
    print("=" * 55)