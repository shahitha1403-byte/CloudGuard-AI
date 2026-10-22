import sqlite3
import os
import uuid
from datetime import datetime


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "database",
    "cloudguard.db"
)


def get_connection():
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )
    return conn


def scan_resources():

    print("\n" + "=" * 60)
    print("CloudGuard AI - Security Scanner")
    print("=" * 60)

    resources = [
        {
            "name": "storage-prod-01",
            "type": "Cloud Storage",
            "status": "At Risk",
            "risks": [
                {
                    "title": "Public Storage Bucket",
                    "description": "Cloud storage bucket is publicly accessible.",
                    "category": "Access Control",
                    "severity": "Critical",
                    "score": 95
                },
                {
                    "title": "Encryption Disabled",
                    "description": "Data encryption is not enabled for the storage resource.",
                    "category": "Data Protection",
                    "severity": "High",
                    "score": 82
                },
                {
                    "title": "Security Logging Disabled",
                    "description": "Security activity logging is disabled.",
                    "category": "Monitoring",
                    "severity": "Medium",
                    "score": 65
                }
            ]
        },
        {
            "name": "vm-production-03",
            "type": "Virtual Machine",
            "status": "At Risk",
            "risks": [
                {
                    "title": "Publicly Exposed Virtual Machine",
                    "description": "Virtual machine is exposed to public network access.",
                    "category": "Network Security",
                    "severity": "High",
                    "score": 85
                },
                {
                    "title": "Open Management Port",
                    "description": "A management port is exposed to unauthorized network access.",
                    "category": "Network Security",
                    "severity": "Critical",
                    "score": 92
                },
                {
                    "title": "VM Monitoring Disabled",
                    "description": "Monitoring is not enabled for the virtual machine.",
                    "category": "Monitoring",
                    "severity": "Medium",
                    "score": 60
                }
            ]
        },
        {
            "name": "identity-service",
            "type": "Identity Service",
            "status": "At Risk",
            "risks": [
                {
                    "title": "Excessive IAM Permissions",
                    "description": "Identity account has permissions beyond the required privilege level.",
                    "category": "Identity and Access",
                    "severity": "Critical",
                    "score": 94
                },
                {
                    "title": "MFA Not Enabled",
                    "description": "Multi-factor authentication is not enabled.",
                    "category": "Identity and Access",
                    "severity": "High",
                    "score": 80
                },
                {
                    "title": "Weak Password Policy",
                    "description": "Password policy does not meet recommended security requirements.",
                    "category": "Identity and Access",
                    "severity": "High",
                    "score": 78
                },
                {
                    "title": "Access Review Missing",
                    "description": "Periodic access review has not been configured.",
                    "category": "Governance",
                    "severity": "Medium",
                    "score": 62
                }
            ]
        },
        {
            "name": "database-main",
            "type": "Cloud Database",
            "status": "Secure",
            "risks": []
        },
        {
            "name": "network-prod-01",
            "type": "Virtual Network",
            "status": "Secure",
            "risks": []
        },
        {
            "name": "backup-service",
            "type": "Backup Service",
            "status": "Secure",
            "risks": []
        }
    ]

    conn = get_connection()
    cursor = conn.cursor()

    try:

        # --------------------------------------------------
        # Read database structure
        # --------------------------------------------------

        cursor.execute("PRAGMA table_info(resources)")
        resource_columns = [
            row[1] for row in cursor.fetchall()
        ]

        cursor.execute("PRAGMA table_info(risks)")
        risk_columns = [
            row[1] for row in cursor.fetchall()
        ]

        resource_count = 0
        new_risk_count = 0

        # --------------------------------------------------
        # Process resources
        # --------------------------------------------------

        for resource in resources:

            resource_name = resource["name"]
            resource_type = resource["type"]
            resource_status = resource["status"]

            print("\n" + resource_name)

            # ----------------------------------------------
            # Find existing resource
            # ----------------------------------------------

            existing_resource = None

            if "resource_name" in resource_columns:

                cursor.execute(
                    """
                    SELECT rowid, *
                    FROM resources
                    WHERE resource_name = ?
                    """,
                    (resource_name,)
                )

                existing_resource = cursor.fetchone()

            elif "name" in resource_columns:

                cursor.execute(
                    """
                    SELECT rowid, *
                    FROM resources
                    WHERE name = ?
                    """,
                    (resource_name,)
                )

                existing_resource = cursor.fetchone()

            # ----------------------------------------------
            # Create resource ID
            # ----------------------------------------------

            resource_id = None

            if existing_resource:

                # Try to locate resource ID from known columns
                if "resource_id" in resource_columns:

                    cursor.execute(
                        """
                        SELECT resource_id
                        FROM resources
                        WHERE resource_name = ?
                        """
                        if "resource_name" in resource_columns
                        else
                        """
                        SELECT resource_id
                        FROM resources
                        WHERE name = ?
                        """,
                        (resource_name,)
                    )

                    result = cursor.fetchone()

                    if result:
                        resource_id = result[0]

            # Generate ID if required
            if not resource_id:
                resource_id = "RES-" + uuid.uuid4().hex[:8].upper()

            # ----------------------------------------------
            # Insert resource
            # ----------------------------------------------

            if not existing_resource:

                columns = []
                values = []

                if "resource_id" in resource_columns:
                    columns.append("resource_id")
                    values.append(resource_id)

                if "resource_name" in resource_columns:
                    columns.append("resource_name")
                    values.append(resource_name)

                elif "name" in resource_columns:
                    columns.append("name")
                    values.append(resource_name)

                if "resource_type" in resource_columns:
                    columns.append("resource_type")
                    values.append(resource_type)

                if "type" in resource_columns:
                    columns.append("type")
                    values.append(resource_type)

                if "status" in resource_columns:
                    columns.append("status")
                    values.append(resource_status)

                if "created_at" in resource_columns:
                    columns.append("created_at")
                    values.append(
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )

                placeholders = ", ".join(
                    ["?"] * len(values)
                )

                cursor.execute(
                    f"""
                    INSERT INTO resources
                    ({", ".join(columns)})
                    VALUES ({placeholders})
                    """,
                    values
                )

            resource_count += 1

            # --------------------------------------------------
            # Process risks
            # --------------------------------------------------

            if not resource["risks"]:

                print("  ✓ Secure")
                continue

            for risk in resource["risks"]:

                title = risk["title"]
                description = risk["description"]
                category = risk["category"]
                severity = risk["severity"]
                score = risk["score"]

                print(
                    f"  {severity}: {title} - {score}"
                )

                # ------------------------------------------
                # Check duplicate risk
                # ------------------------------------------

                duplicate = False

                if (
                    "resource_id" in risk_columns
                    and "title" in risk_columns
                ):

                    cursor.execute(
                        """
                        SELECT id
                        FROM risks
                        WHERE resource_id = ?
                        AND title = ?
                        """,
                        (
                            resource_id,
                            title
                        )
                    )

                    if cursor.fetchone():
                        duplicate = True

                if duplicate:
                    continue

                # ------------------------------------------
                # Create risk ID
                # ------------------------------------------

                risk_id = (
                    "RISK-" +
                    datetime.now().strftime("%Y%m%d%H%M%S") +
                    "-" +
                    uuid.uuid4().hex[:6].upper()
                )

                # ------------------------------------------
                # Build risk INSERT
                # ------------------------------------------

                columns = []
                values = []

                if "risk_id" in risk_columns:
                    columns.append("risk_id")
                    values.append(risk_id)

                if "resource_id" in risk_columns:
                    columns.append("resource_id")
                    values.append(resource_id)

                if "title" in risk_columns:
                    columns.append("title")
                    values.append(title)

                if "description" in risk_columns:
                    columns.append("description")
                    values.append(description)

                if "category" in risk_columns:
                    columns.append("category")
                    values.append(category)

                if "severity" in risk_columns:
                    columns.append("severity")
                    values.append(severity)

                if "risk_score" in risk_columns:
                    columns.append("risk_score")
                    values.append(score)

                elif "score" in risk_columns:
                    columns.append("score")
                    values.append(score)

                if "status" in risk_columns:
                    columns.append("status")
                    values.append("Open")

                if "detected_at" in risk_columns:
                    columns.append("detected_at")
                    values.append(
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )

                placeholders = ", ".join(
                    ["?"] * len(values)
                )

                cursor.execute(
                    f"""
                    INSERT INTO risks
                    ({", ".join(columns)})
                    VALUES ({placeholders})
                    """,
                    values
                )

                new_risk_count += 1

        conn.commit()

        print("\n" + "=" * 60)
        print("SECURITY SCAN COMPLETED")
        print("=" * 60)
        print(f"Resources Scanned : {resource_count}")
        print(f"New Risks Detected: {new_risk_count}")
        print("=" * 60)

        return {
            "resources_scanned": resource_count,
            "risks_detected": new_risk_count
        }

    except Exception as e:

        conn.rollback()

        print("\nSecurity Scanner Error:", e)

        raise

    finally:

        conn.close()


if __name__ == "__main__":
    scan_resources()