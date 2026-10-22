import sqlite3
from datetime import datetime
from pathlib import Path
import uuid


# ============================================================
# CLOUDGUARD AI - REMEDIATION ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "cloudguard.db"


class RemediationEngine:

    def __init__(self):
        self.db_path = DB_PATH

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    # ========================================================
    # GET TABLE COLUMNS
    # ========================================================

    def get_columns(self, table_name):

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            f"PRAGMA table_info({table_name})"
        )

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
    # GET RISK VALUE
    # ========================================================

    def get_value(self, risk, possible_names):

        for name in possible_names:

            if name in risk:

                value = risk[name]

                if value is not None:
                    return value

        return ""

    # ========================================================
    # GENERATE REMEDIATION RECOMMENDATION
    # ========================================================

    def get_recommendation(self, risk_name):

        name = str(risk_name).lower()

        recommendations = {

            "public storage bucket":
                "Disable public access and enable private access controls.",

            "encryption disabled":
                "Enable encryption for the affected cloud resource.",

            "publicly exposed virtual machine":
                "Restrict public network access and allow only trusted sources.",

            "open management port":
                "Close unnecessary management ports and restrict administrative access.",

            "excessive iam permissions":
                "Apply least-privilege IAM permissions and remove unnecessary privileges.",

            "mfa not enabled":
                "Enable Multi-Factor Authentication for privileged accounts.",

            "weak password policy":
                "Enforce a strong password policy with minimum length and complexity.",

            "access review missing":
                "Perform periodic access reviews and remove unnecessary accounts.",

            "security logging disabled":
                "Enable centralized security logging and monitoring.",

            "vm monitoring disabled":
                "Enable VM monitoring and security event collection."
        }

        for key, recommendation in recommendations.items():

            if key in name:
                return recommendation

        return (
            "Review the affected resource configuration "
            "and apply appropriate security controls."
        )

    # ========================================================
    # CREATE REMEDIATION RECORD
    # ========================================================

    def create_remediation(
        self,
        risk,
        recommendation
    ):

        columns = self.get_columns(
            "remediation"
        )

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        remediation_id = (
            "REM-" +
            uuid.uuid4().hex[:8].upper()
        )

        risk_id = self.get_value(
            risk,
            [
                "id",
                "risk_id",
                "event_id"
            ]
        )

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

        values_map = {

            "remediation_id":
                remediation_id,

            "risk_id":
                risk_id,

            "risk_name":
                risk_name,

            "resource_name":
                resource,

            "resource":
                resource,

            "recommendation":
                recommendation,

            "action":
                recommendation,

            "status":
                "PENDING_APPROVAL",

            "approval_status":
                "PENDING",

            "approved":
                0,

            "verification_status":
                "NOT_VERIFIED",

            "created_at":
                now,

            "updated_at":
                now,

            "approved_at":
                None,

            "completed_at":
                None
        }

        insert_columns = []
        insert_values = []

        for column in columns:

            if column == "id":
                continue

            if column in values_map:

                value = values_map[column]

                # Skip None only if column is not NOT NULL.
                # Required fields are handled below.
                insert_columns.append(column)
                insert_values.append(value)

        # ----------------------------------------------------
        # Remove optional NULL fields if table does not allow
        # them through a simple safe fallback.
        # ----------------------------------------------------

        query_columns = []
        query_values = []

        for column, value in zip(
            insert_columns,
            insert_values
        ):

            if value is not None:
                query_columns.append(column)
                query_values.append(value)

        # ----------------------------------------------------
        # Insert
        # ----------------------------------------------------

        connection = self.get_connection()
        cursor = connection.cursor()

        placeholders = ", ".join(
            ["?"] * len(query_values)
        )

        query = f"""
            INSERT INTO remediation
            ({", ".join(query_columns)})
            VALUES
            ({placeholders})
        """

        cursor.execute(
            query,
            query_values
        )

        connection.commit()
        connection.close()

        return remediation_id

    # ========================================================
    # ADMIN APPROVAL
    # ========================================================

    def approve_remediation(
        self,
        remediation_id
    ):

        columns = self.get_columns(
            "remediation"
        )

        connection = self.get_connection()
        cursor = connection.cursor()

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        updates = []
        values = []

        if "status" in columns:

            updates.append("status = ?")
            values.append("APPROVED")

        if "approval_status" in columns:

            updates.append(
                "approval_status = ?"
            )
            values.append("APPROVED")

        if "approved" in columns:

            updates.append("approved = ?")
            values.append(1)

        if "approved_at" in columns:

            updates.append(
                "approved_at = ?"
            )
            values.append(now)

        if "updated_at" in columns:

            updates.append(
                "updated_at = ?"
            )
            values.append(now)

        if not updates:

            connection.close()

            return False

        values.append(remediation_id)

        query = f"""
            UPDATE remediation
            SET {", ".join(updates)}
            WHERE
                remediation_id = ?
                OR id = ?
        """

        # Handle tables that may use id instead of remediation_id
        if "remediation_id" in columns:

            values = values[:-1] + [
                remediation_id,
                remediation_id
            ]

        else:

            query = f"""
                UPDATE remediation
                SET {", ".join(updates)}
                WHERE id = ?
            """

            values = values[:-1] + [
                remediation_id
            ]

        cursor.execute(
            query,
            values
        )

        connection.commit()

        updated = cursor.rowcount

        connection.close()

        return updated > 0

    # ========================================================
    # EXECUTE REMEDIATION
    # ========================================================

    def execute_remediation(
        self,
        remediation_id
    ):

        columns = self.get_columns(
            "remediation"
        )

        connection = self.get_connection()
        cursor = connection.cursor()

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        updates = []
        values = []

        if "status" in columns:

            updates.append(
                "status = ?"
            )

            values.append(
                "REMEDIATED"
            )

        if "verification_status" in columns:

            updates.append(
                "verification_status = ?"
            )

            values.append(
                "VERIFIED"
            )

        if "completed_at" in columns:

            updates.append(
                "completed_at = ?"
            )

            values.append(now)

        if "updated_at" in columns:

            updates.append(
                "updated_at = ?"
            )

            values.append(now)

        if not updates:

            connection.close()

            return False

        if "remediation_id" in columns:

            query = f"""
                UPDATE remediation
                SET {", ".join(updates)}
                WHERE remediation_id = ?
            """

        else:

            query = f"""
                UPDATE remediation
                SET {", ".join(updates)}
                WHERE id = ?
            """

        values.append(remediation_id)

        cursor.execute(
            query,
            values
        )

        connection.commit()

        updated = cursor.rowcount

        connection.close()

        return updated > 0

    # ========================================================
    # VERIFY REMEDIATION
    # ========================================================

    def verify_remediation(
        self,
        remediation_id
    ):

        columns = self.get_columns(
            "remediation"
        )

        connection = self.get_connection()
        cursor = connection.cursor()

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        updates = []
        values = []

        if "verification_status" in columns:

            updates.append(
                "verification_status = ?"
            )

            values.append(
                "VERIFIED"
            )

        if "status" in columns:

            updates.append(
                "status = ?"
            )

            values.append(
                "VERIFIED"
            )

        if "updated_at" in columns:

            updates.append(
                "updated_at = ?"
            )

            values.append(now)

        if not updates:

            connection.close()

            return False

        if "remediation_id" in columns:

            query = f"""
                UPDATE remediation
                SET {", ".join(updates)}
                WHERE remediation_id = ?
            """

        else:

            query = f"""
                UPDATE remediation
                SET {", ".join(updates)}
                WHERE id = ?
            """

        values.append(remediation_id)

        cursor.execute(
            query,
            values
        )

        connection.commit()

        updated = cursor.rowcount

        connection.close()

        return updated > 0

    # ========================================================
    # AUDIT LOG
    # ========================================================

    def create_audit_log(
        self,
        action,
        description
    ):

        columns = self.get_columns(
            "audit_logs"
        )

        connection = self.get_connection()
        cursor = connection.cursor()

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        event_id = (
            "AUD-REM-" +
            uuid.uuid4().hex[:8].upper()
        )

        values_map = {

            "event_id":
                event_id,

            "action":
                action,

            "event_type":
                action,

            "description":
                description,

            "details":
                description,

            "username":
                "admin",

            "user":
                "admin",

            "severity":
                "INFO",

            "created_at":
                now,

            "timestamp":
                now,

            "logged_at":
                now
        }

        insert_columns = []
        insert_values = []

        for column in columns:

            if column == "id":
                continue

            if column in values_map:

                insert_columns.append(
                    column
                )

                insert_values.append(
                    values_map[column]
                )

        if not insert_columns:

            connection.close()

            return False

        placeholders = ", ".join(
            ["?"] * len(insert_values)
        )

        query = f"""
            INSERT INTO audit_logs
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

        return True

    # ========================================================
    # FULL REMEDIATION WORKFLOW
    # ========================================================

    def run(self):

        print("=" * 60)
        print("CloudGuard AI - Remediation Engine")
        print("=" * 60)

        risks = self.get_risks()

        print(
            f"Risks Available : {len(risks)}"
        )

        if not risks:

            print(
                "No risks available for remediation."
            )

            return

        created = 0

        # ----------------------------------------------------
        # Process first 10 detected risks
        # ----------------------------------------------------

        for risk in risks[:10]:

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

            if not risk_name:

                risk_name = "Unknown Security Risk"

            recommendation = self.get_recommendation(
                risk_name
            )

            remediation_id = self.create_remediation(
                risk,
                recommendation
            )

            self.create_audit_log(
                "REMEDIATION_CREATED",
                (
                    f"Remediation {remediation_id} "
                    f"created for {risk_name} "
                    f"on {resource}."
                )
            )

            print()
            print(
                f"Risk          : {risk_name}"
            )
            print(
                f"Resource      : {resource}"
            )
            print(
                f"Remediation   : {remediation_id}"
            )
            print(
                "Status        : PENDING_APPROVAL"
            )

            created += 1

        print()
        print("=" * 60)
        print("REMEDIATION SUMMARY")
        print("=" * 60)

        print(
            f"Remediation Records Created : {created}"
        )

        print(
            "Admin Approval              : PENDING"
        )

        print(
            "Automatic Execution         : DISABLED"
        )

        print(
            "Verification                : PENDING"
        )

        print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    engine = RemediationEngine()

    engine.run()

    print()
    print(
        "Remediation analysis completed successfully."
    )