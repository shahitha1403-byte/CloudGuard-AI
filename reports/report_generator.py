import sqlite3
from datetime import datetime
from pathlib import Path
import csv
import html


# ============================================================
# CLOUDGUARD AI - SECURITY REPORT GENERATOR
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "cloudguard.db"
REPORT_DIR = BASE_DIR / "reports" / "generated"

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


class SecurityReportGenerator:

    def __init__(self):
        self.db_path = DB_PATH

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    # ========================================================
    # GET TABLE DATA
    # ========================================================

    def get_table_data(self, table_name):

        connection = self.get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                f"SELECT * FROM {table_name}"
            )

            rows = cursor.fetchall()

            columns = [
                description[0]
                for description in cursor.description
            ]

        except sqlite3.Error:

            rows = []
            columns = []

        connection.close()

        return columns, rows

    # ========================================================
    # GET RISKS
    # ========================================================

    def get_risks(self):

        columns, rows = self.get_table_data(
            "risks"
        )

        return [
            dict(zip(columns, row))
            for row in rows
        ]

    # ========================================================
    # GET RISK VALUE
    # ========================================================

    def get_value(self, row, names):

        for name in names:

            if name in row:

                value = row[name]

                if value is not None:
                    return value

        return ""

    # ========================================================
    # RISK SUMMARY
    # ========================================================

    def calculate_risk_summary(self, risks):

        critical = 0
        high = 0
        medium = 0
        low = 0

        for risk in risks:

            severity = str(
                self.get_value(
                    risk,
                    [
                        "severity",
                        "risk_level",
                        "level"
                    ]
                )
            ).lower()

            if "critical" in severity:
                critical += 1

            elif "high" in severity:
                high += 1

            elif "medium" in severity:
                medium += 1

            else:
                low += 1

        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(risks)
        }

    # ========================================================
    # SECURITY POSTURE SCORE
    # ========================================================

    def calculate_posture_score(
        self,
        summary
    ):

        total = summary["total"]

        if total == 0:
            return 100

        penalty = (
            summary["critical"] * 15 +
            summary["high"] * 8 +
            summary["medium"] * 4 +
            summary["low"] * 1
        )

        score = max(
            0,
            100 - penalty
        )

        return score

    # ========================================================
    # GENERATE CSV REPORT
    # ========================================================

    def generate_csv(
        self,
        risks
    ):

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        file_path = (
            REPORT_DIR /
            f"cloudguard_security_report_{timestamp}.csv"
        )

        with open(
            file_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                [
                    "Risk ID",
                    "Resource",
                    "Risk",
                    "Severity",
                    "Risk Score",
                    "Status"
                ]
            )

            for risk in risks:

                risk_id = self.get_value(
                    risk,
                    [
                        "id",
                        "risk_id",
                        "event_id"
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

                risk_name = self.get_value(
                    risk,
                    [
                        "risk_type",
                        "risk_name",
                        "title",
                        "name"
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

                risk_score = self.get_value(
                    risk,
                    [
                        "risk_score",
                        "score"
                    ]
                )

                status = self.get_value(
                    risk,
                    [
                        "status",
                        "state"
                    ]
                )

                writer.writerow(
                    [
                        risk_id,
                        resource,
                        risk_name,
                        severity,
                        risk_score,
                        status
                    ]
                )

        return file_path

    # ========================================================
    # GENERATE HTML REPORT
    # ========================================================

    def generate_html(
        self,
        risks,
        summary,
        posture_score
    ):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        safe_time = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        file_path = (
            REPORT_DIR /
            f"cloudguard_security_report_{safe_time}.html"
        )

        rows_html = ""

        for risk in risks:

            risk_id = self.get_value(
                risk,
                [
                    "id",
                    "risk_id",
                    "event_id"
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

            risk_name = self.get_value(
                risk,
                [
                    "risk_type",
                    "risk_name",
                    "title",
                    "name"
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

            score = self.get_value(
                risk,
                [
                    "risk_score",
                    "score"
                ]
            )

            status = self.get_value(
                risk,
                [
                    "status",
                    "state"
                ]
            )

            rows_html += f"""
            <tr>
                <td>{html.escape(str(risk_id))}</td>
                <td>{html.escape(str(resource))}</td>
                <td>{html.escape(str(risk_name))}</td>
                <td>{html.escape(str(severity))}</td>
                <td>{html.escape(str(score))}</td>
                <td>{html.escape(str(status))}</td>
            </tr>
            """

        report_html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>CloudGuard AI Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f4f6f8;
    color: #222;
}}

.header {{
    background: #111827;
    color: white;
    padding: 30px;
    border-radius: 12px;
}}

.header h1 {{
    margin: 0;
}}

.cards {{
    display: flex;
    gap: 15px;
    margin: 25px 0;
    flex-wrap: wrap;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    min-width: 150px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.card h3 {{
    margin-top: 0;
}}

.score {{
    font-size: 30px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}

th {{
    background: #1f2937;
    color: white;
    padding: 12px;
    text-align: left;
}}

td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
}}

.footer {{
    margin-top: 30px;
    color: #666;
    font-size: 13px;
}}

</style>

</head>

<body>

<div class="header">

<h1>CloudGuard AI</h1>

<h2>Cloud Security Assessment Report</h2>

<p>Generated: {html.escape(timestamp)}</p>

</div>

<div class="cards">

<div class="card">
<h3>Total Risks</h3>
<div class="score">{summary["total"]}</div>
</div>

<div class="card">
<h3>Critical</h3>
<div class="score">{summary["critical"]}</div>
</div>

<div class="card">
<h3>High</h3>
<div class="score">{summary["high"]}</div>
</div>

<div class="card">
<h3>Medium</h3>
<div class="score">{summary["medium"]}</div>
</div>

<div class="card">
<h3>Low</h3>
<div class="score">{summary["low"]}</div>
</div>

<div class="card">
<h3>Security Posture</h3>
<div class="score">{posture_score}%</div>
</div>

</div>

<h2>Detected Security Risks</h2>

<table>

<thead>

<tr>
<th>Risk ID</th>
<th>Resource</th>
<th>Risk</th>
<th>Severity</th>
<th>Risk Score</th>
<th>Status</th>
</tr>

</thead>

<tbody>

{rows_html}

</tbody>

</table>

<div class="footer">

<p>
CloudGuard AI - Intelligent Cloud Security
Posture, Risk Prediction & Automated Remediation Platform
</p>

<p>
This report was generated automatically by the
CloudGuard AI security monitoring platform.
</p>

</div>

</body>

</html>
"""

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(report_html)

        return file_path

    # ========================================================
    # RUN REPORT GENERATOR
    # ========================================================

    def run(self):

        print("=" * 65)
        print("CloudGuard AI - Security Report Generator")
        print("=" * 65)

        risks = self.get_risks()

        summary = self.calculate_risk_summary(
            risks
        )

        posture_score = self.calculate_posture_score(
            summary
        )

        print()
        print(
            f"Total Risks       : {summary['total']}"
        )

        print(
            f"Critical Risks    : {summary['critical']}"
        )

        print(
            f"High Risks        : {summary['high']}"
        )

        print(
            f"Medium Risks      : {summary['medium']}"
        )

        print(
            f"Low Risks         : {summary['low']}"
        )

        print(
            f"Security Posture  : {posture_score}%"
        )

        print()
        print("Generating reports...")

        csv_file = self.generate_csv(
            risks
        )

        html_file = self.generate_html(
            risks,
            summary,
            posture_score
        )

        print()
        print("=" * 65)
        print("REPORT GENERATION COMPLETED")
        print("=" * 65)

        print(
            f"CSV Report  : {csv_file}"
        )

        print(
            f"HTML Report : {html_file}"
        )

        print()
        print(
            "Reports saved successfully."
        )

        print("=" * 65)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    generator = SecurityReportGenerator()

    generator.run()