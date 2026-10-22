import sqlite3
import os
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
    return sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )


def analyze_risk(title, severity, score, category):

    explanations = {

        "Public Storage Bucket":
            "The cloud storage resource is publicly accessible. "
            "Unauthorized users may access sensitive information.",

        "Excessive IAM Permissions":
            "An identity has more permissions than required. "
            "This increases the risk of privilege abuse and account compromise.",

        "Open Management Port":
            "A management port is exposed to external networks. "
            "Attackers may attempt unauthorized remote access.",

        "Publicly Exposed Virtual Machine":
            "The virtual machine is publicly reachable and may be targeted "
            "by automated attacks or unauthorized users.",

        "Encryption Disabled":
            "Data is not protected with encryption. "
            "Sensitive information may be exposed if the resource is compromised.",

        "MFA Not Enabled":
            "Multi-factor authentication is disabled. "
            "Compromised credentials could allow unauthorized access.",

        "Weak Password Policy":
            "The password policy does not provide sufficient protection "
            "against password guessing and credential attacks.",

        "Security Logging Disabled":
            "Security activity is not being logged properly. "
            "This can reduce visibility during security incidents.",

        "Access Review Missing":
            "User access has not been reviewed regularly. "
            "Unused or unnecessary permissions may remain active.",

        "VM Monitoring Disabled":
            "Monitoring is disabled for the virtual machine. "
            "Suspicious activities may not be detected quickly."
    }

    recommendations = {

        "Public Storage Bucket":
            "Restrict public access and enable private bucket policies.",

        "Excessive IAM Permissions":
            "Apply least-privilege permissions and remove unnecessary access.",

        "Open Management Port":
            "Restrict management ports using firewall and network security rules.",

        "Publicly Exposed Virtual Machine":
            "Remove unnecessary public exposure and use private network access.",

        "Encryption Disabled":
            "Enable encryption for data at rest and in transit.",

        "MFA Not Enabled":
            "Enable multi-factor authentication for privileged accounts.",

        "Weak Password Policy":
            "Enforce strong password complexity and account protection policies.",

        "Security Logging Disabled":
            "Enable centralized security logging and monitoring.",

        "Access Review Missing":
            "Perform periodic access reviews and remove unnecessary permissions.",

        "VM Monitoring Disabled":
            "Enable continuous monitoring and security alerts."
    }

    explanation = explanations.get(
        title,
        "This configuration may introduce a security risk "
        "to the cloud environment."
    )

    recommendation = recommendations.get(
        title,
        "Review the cloud configuration and apply recommended security controls."
    )

    if score >= 90:

        impact = "Severe"
        priority = "Immediate"
        prediction = "Very High"

    elif score >= 75:

        impact = "High"
        priority = "High Priority"
        prediction = "High"

    elif score >= 50:

        impact = "Moderate"
        priority = "Normal Priority"
        prediction = "Moderate"

    else:

        impact = "Low"
        priority = "Low Priority"
        prediction = "Low"

    # Detailed impact analysis
    impact_analysis = (
        f"The detected {severity.lower()} severity risk "
        f"has a risk score of {score}. "
        f"If this issue remains unresolved, it may negatively affect "
        f"the {category.lower()} security of the cloud environment. "
        f"Potential consequences include unauthorized access, "
        f"data exposure, service disruption, or reduced security visibility."
    )

    # Risk prediction
    risk_prediction = (
        f"Based on the current risk score of {score}, "
        f"the predicted future risk level is {prediction}. "
        f"Immediate security attention is recommended."
    )

    return {
        "explanation": explanation,
        "impact": impact,
        "impact_analysis": impact_analysis,
        "priority": priority,
        "prediction": prediction,
        "risk_prediction": risk_prediction,
        "recommendation": recommendation,
        "category": category,
        "severity": severity,
        "score": score
    }


def run_ai_analysis():

    print("\n" + "=" * 60)
    print("CloudGuard AI - AI Risk Analysis")
    print("=" * 60)

    conn = get_connection()
    cursor = conn.cursor()

    try:

        # --------------------------------------------------
        # Read risks
        # --------------------------------------------------

        cursor.execute("""
            SELECT
                risk_id,
                title,
                category,
                severity,
                risk_score
            FROM risks
            ORDER BY risk_score DESC
        """)

        risks = cursor.fetchall()

        # --------------------------------------------------
        # Read AI table structure
        # --------------------------------------------------

        cursor.execute(
            "PRAGMA table_info(ai_analysis)"
        )

        ai_columns = [
            row[1]
            for row in cursor.fetchall()
        ]

        print("AI Analysis Columns:", ai_columns)

        analyzed_count = 0

        # --------------------------------------------------
        # Analyze every risk
        # --------------------------------------------------

        for risk in risks:

            risk_id = risk[0]
            title = risk[1]
            category = risk[2]
            severity = risk[3]
            score = risk[4]

            result = analyze_risk(
                title,
                severity,
                score,
                category
            )

            # ----------------------------------------------
            # Check duplicate
            # ----------------------------------------------

            duplicate = False

            if "risk_id" in ai_columns:

                cursor.execute(
                    """
                    SELECT rowid
                    FROM ai_analysis
                    WHERE risk_id = ?
                    """,
                    (risk_id,)
                )

                if cursor.fetchone():
                    duplicate = True

            if duplicate:
                print(
                    f"↪ Already analyzed: {title}"
                )
                continue

            # ----------------------------------------------
            # Build dynamic INSERT
            # ----------------------------------------------

            columns = []
            values = []

            # Risk ID
            if "risk_id" in ai_columns:
                columns.append("risk_id")
                values.append(risk_id)

            # Explanation
            if "explanation" in ai_columns:
                columns.append("explanation")
                values.append(result["explanation"])

            # Impact
            if "impact" in ai_columns:
                columns.append("impact")
                values.append(result["impact"])

            # IMPORTANT:
            # Your database requires impact_analysis
            if "impact_analysis" in ai_columns:
                columns.append("impact_analysis")
                values.append(result["impact_analysis"])

            # Priority
            if "priority" in ai_columns:
                columns.append("priority")
                values.append(result["priority"])

            # Prediction
            if "prediction" in ai_columns:
                columns.append("prediction")
                values.append(result["prediction"])

            if "risk_prediction" in ai_columns:
                columns.append("risk_prediction")
                values.append(result["risk_prediction"])

            # Recommendation
            if "recommendation" in ai_columns:
                columns.append("recommendation")
                values.append(result["recommendation"])

            if "ai_recommendation" in ai_columns:
                columns.append("ai_recommendation")
                values.append(result["recommendation"])

            # Risk score
            if "risk_score" in ai_columns:
                columns.append("risk_score")
                values.append(score)

            # Severity
            if "severity" in ai_columns:
                columns.append("severity")
                values.append(severity)

            # Created time
            current_time = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            if "created_at" in ai_columns:
                columns.append("created_at")
                values.append(current_time)

            if "analyzed_at" in ai_columns:
                columns.append("analyzed_at")
                values.append(current_time)

            # ----------------------------------------------
            # Insert AI result
            # ----------------------------------------------

            if columns:

                placeholders = ", ".join(
                    ["?"] * len(values)
                )

                cursor.execute(
                    f"""
                    INSERT INTO ai_analysis
                    ({", ".join(columns)})
                    VALUES ({placeholders})
                    """,
                    values
                )

                analyzed_count += 1

                print(
                    f"✓ {title} | "
                    f"{severity} | "
                    f"Score: {score} | "
                    f"Impact: {result['impact']}"
                )

        conn.commit()

        print("\n" + "=" * 60)
        print("AI ANALYSIS COMPLETED")
        print("=" * 60)
        print(f"Risks Found    : {len(risks)}")
        print(f"AI Records Saved: {analyzed_count}")
        print("=" * 60)

        return {
            "risks_found": len(risks),
            "analyzed": analyzed_count
        }

    except Exception as e:

        conn.rollback()

        print("\nAI Analysis Error:", e)

        raise

    finally:

        conn.close()


if __name__ == "__main__":
    run_ai_analysis()