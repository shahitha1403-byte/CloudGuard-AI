from flask import Flask, render_template, request, redirect, url_for, session
import os
import sqlite3
from datetime import datetime

from database.database import initialize_database, get_connection
from security.scanner import scan_resources


app = Flask(__name__)

app.secret_key = "cloudguard-ai-secret-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database", "cloudguard.db")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

initialize_database()


# --------------------------------------------------
# LOGIN CHECK
# --------------------------------------------------

def login_required():
    return "username" in session


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin123":

            session["username"] = username

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    statistics = {
        "total_resources": 0,
        "total_risks": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    try:

        cursor.execute("SELECT COUNT(*) FROM resources")
        statistics["total_resources"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM risks")
        statistics["total_risks"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM risks WHERE LOWER(severity) = 'critical'"
        )
        statistics["critical"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM risks WHERE LOWER(severity) = 'high'"
        )
        statistics["high"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM risks WHERE LOWER(severity) = 'medium'"
        )
        statistics["medium"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM risks WHERE LOWER(severity) = 'low'"
        )
        statistics["low"] = cursor.fetchone()[0]

    except Exception as e:

        print("Dashboard statistics error:", e)

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        statistics=statistics
    )


# --------------------------------------------------
# RESOURCES
# --------------------------------------------------

@app.route("/resources")
def resources():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM resources")
        resources_data = cursor.fetchall()

    except Exception as e:

        print("Resources error:", e)
        resources_data = []

    finally:
        conn.close()

    return render_template(
        "resources.html",
        resources=resources_data
    )


# --------------------------------------------------
# RISKS
# --------------------------------------------------

@app.route("/risks")
def risks():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM risks ORDER BY risk_score DESC")
        risks_data = cursor.fetchall()

    except Exception as e:

        print("Risks error:", e)
        risks_data = []

    finally:
        conn.close()

    return render_template(
        "risks.html",
        risks=risks_data
    )


# --------------------------------------------------
# AI ANALYSIS
# --------------------------------------------------

@app.route("/ai-analysis")
def ai_analysis():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM ai_analysis")
        analysis_data = cursor.fetchall()

    except Exception as e:

        print("AI analysis error:", e)
        analysis_data = []

    finally:
        conn.close()

    return render_template(
        "ai_analysis.html",
        analysis=analysis_data
    )


# --------------------------------------------------
# COMPLIANCE
# --------------------------------------------------

@app.route("/compliance")
def compliance():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM compliance")
        compliance_data = cursor.fetchall()

    except Exception as e:

        print("Compliance error:", e)
        compliance_data = []

    finally:
        conn.close()

    return render_template(
        "compliance.html",
        compliance=compliance_data
    )


# --------------------------------------------------
# REMEDIATION
# --------------------------------------------------

@app.route("/remediation")
def remediation():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM remediation")
        remediation_data = cursor.fetchall()

    except Exception as e:

        print("Remediation error:", e)
        remediation_data = []

    finally:
        conn.close()

    return render_template(
        "remediation.html",
        remediation=remediation_data
    )


# --------------------------------------------------
# REPORTS
# --------------------------------------------------

@app.route("/reports")
def reports():

    if not login_required():
        return redirect(url_for("login"))

    reports_data = []

    reports_dir = os.path.join(BASE_DIR, "reports", "generated")

    if os.path.exists(reports_dir):

        for filename in os.listdir(reports_dir):

            filepath = os.path.join(reports_dir, filename)

            if os.path.isfile(filepath):

                reports_data.append({
                    "name": filename,
                    "created_at": datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })

    return render_template(
        "reports.html",
        reports=reports_data
    )


# --------------------------------------------------
# AUDIT LOGS
# --------------------------------------------------

@app.route("/audit")
def audit():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            "SELECT * FROM audit_logs ORDER BY rowid DESC"
        )

        audit_data = cursor.fetchall()

    except Exception as e:

        print("Audit error:", e)
        audit_data = []

    finally:
        conn.close()

    return render_template(
        "audit.html",
        audit_logs=audit_data
    )


# --------------------------------------------------
# SECURITY SCAN
# --------------------------------------------------

@app.route("/security-scan", methods=["GET", "POST"])
def security_scan():

    if not login_required():
        return redirect(url_for("login"))

    scan_completed = False
    resources_scanned = 0
    risks_detected = 0

    if request.method == "POST":

        print("\n" + "=" * 60)
        print("CloudGuard AI - Security Scan Started")
        print("=" * 60)

        try:

            # Run the existing security scanner
            scan_result = scan_resources()

            print("Scanner Result:", scan_result)

            # Read latest database values
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM resources")
            resources_scanned = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM risks")
            risks_detected = cursor.fetchone()[0]

            conn.close()

            scan_completed = True

            print("Resources Scanned:", resources_scanned)
            print("Risks Detected:", risks_detected)
            print("Security Scan Completed Successfully")

        except Exception as e:

            print("Security Scan Error:", e)

    return render_template(
        "security_scan.html",
        scan_completed=scan_completed,
        resources_scanned=resources_scanned,
        risks_detected=risks_detected
    )


# --------------------------------------------------
# BACKUP & RECOVERY
# --------------------------------------------------

@app.route("/backup")
def backup():

    if not login_required():
        return redirect(url_for("login"))

    backups = []

    if os.path.exists(BACKUP_DIR):

        for filename in os.listdir(BACKUP_DIR):

            if filename.endswith(".db"):

                filepath = os.path.join(BACKUP_DIR, filename)

                backups.append({
                    "name": filename,
                    "created_at": datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })

    backups.sort(
        key=lambda x: x["created_at"],
        reverse=True
    )

    return render_template(
        "backup.html",
        backups=backups
    )


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():

    return {
        "status": "online",
        "application": "CloudGuard AI",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("CloudGuard AI - Intelligent Cloud Security Platform")
    print("=" * 60)
    print("Application: http://127.0.0.1:5000")
    print("Login Username: admin")
    print("Login Password: admin123")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )