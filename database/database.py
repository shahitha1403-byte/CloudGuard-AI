import sqlite3
import os
from datetime import datetime


# ---------------------------------------------------------
# DATABASE PATH
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "cloudguard.db")


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_connection():
    """
    Creates and returns a SQLite database connection.
    """

    os.makedirs(DATABASE_DIR, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    # -----------------------------------------------------
    # USERS TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # CLOUD RESOURCES TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_id TEXT UNIQUE NOT NULL,
            resource_name TEXT NOT NULL,
            provider TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            region TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # RISKS TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk_id TEXT UNIQUE NOT NULL,
            resource_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT DEFAULT 'Open',
            detected_at TEXT NOT NULL,
            FOREIGN KEY(resource_id) REFERENCES resources(resource_id)
        )
    """)

    # -----------------------------------------------------
    # AI ANALYSIS TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk_id TEXT NOT NULL,
            explanation TEXT NOT NULL,
            impact_analysis TEXT NOT NULL,
            prediction TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            confidence INTEGER DEFAULT 0,
            analyzed_at TEXT NOT NULL,
            FOREIGN KEY(risk_id) REFERENCES risks(risk_id)
        )
    """)

    # -----------------------------------------------------
    # COMPLIANCE TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS compliance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework TEXT NOT NULL,
            control_id TEXT NOT NULL,
            control_name TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER NOT NULL,
            finding TEXT,
            checked_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # REMEDIATION TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk_id TEXT NOT NULL,
            action TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            approval_status TEXT DEFAULT 'Pending',
            approved_by TEXT,
            executed_at TEXT,
            verification_status TEXT DEFAULT 'Pending',
            verification_message TEXT,
            FOREIGN KEY(risk_id) REFERENCES risks(risk_id)
        )
    """)

    # -----------------------------------------------------
    # AUDIT LOG TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            username TEXT,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            resource_id TEXT,
            severity TEXT DEFAULT 'Info',
            status TEXT DEFAULT 'Completed',
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # REPORTS TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            report_type TEXT NOT NULL,
            generated_by TEXT NOT NULL,
            format TEXT DEFAULT 'PDF',
            status TEXT DEFAULT 'Generated',
            file_path TEXT,
            generated_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # SECURITY POSTURE TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_posture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            score INTEGER NOT NULL,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            calculated_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # BACKUP HISTORY TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backup_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_name TEXT NOT NULL,
            backup_path TEXT NOT NULL,
            backup_size INTEGER DEFAULT 0,
            status TEXT DEFAULT 'Success',
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # DEFAULT ADMIN USER
    # -----------------------------------------------------

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    )

    existing_user = cursor.fetchone()

    if existing_user is None:

        cursor.execute("""
            INSERT INTO users
            (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            "admin",
            "admin123",
            "admin",
            datetime.now().isoformat()
        ))

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# INSERT RESOURCE
# ---------------------------------------------------------

def add_resource(
    resource_id,
    resource_name,
    provider,
    resource_type,
    region,
    status,
    risk_count=0
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO resources
        (
            resource_id,
            resource_name,
            provider,
            resource_type,
            region,
            status,
            risk_count,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        resource_id,
        resource_name,
        provider,
        resource_type,
        region,
        status,
        risk_count,
        datetime.now().isoformat()
    ))

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# INSERT RISK
# ---------------------------------------------------------

def add_risk(
    risk_id,
    resource_id,
    title,
    description,
    category,
    severity,
    risk_score,
    status="Open"
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO risks
        (
            risk_id,
            resource_id,
            title,
            description,
            category,
            severity,
            risk_score,
            status,
            detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        risk_id,
        resource_id,
        title,
        description,
        category,
        severity,
        risk_score,
        status,
        datetime.now().isoformat()
    ))

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# ADD AUDIT LOG
# ---------------------------------------------------------

def add_audit_log(
    event_id,
    username,
    event_type,
    description,
    resource_id=None,
    severity="Info",
    status="Completed"
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO audit_logs
        (
            event_id,
            username,
            event_type,
            description,
            resource_id,
            severity,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_id,
        username,
        event_type,
        description,
        resource_id,
        severity,
        status,
        datetime.now().isoformat()
    ))

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# GET RESOURCES
# ---------------------------------------------------------

def get_resources():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM resources
        ORDER BY id DESC
    """)

    resources = cursor.fetchall()

    connection.close()

    return resources


# ---------------------------------------------------------
# GET RISKS
# ---------------------------------------------------------

def get_risks():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM risks
        ORDER BY risk_score DESC
    """)

    risks = cursor.fetchall()

    connection.close()

    return risks


# ---------------------------------------------------------
# GET AUDIT LOGS
# ---------------------------------------------------------

def get_audit_logs():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
    """)

    logs = cursor.fetchall()

    connection.close()

    return logs


# ---------------------------------------------------------
# DATABASE STATISTICS
# ---------------------------------------------------------

def get_statistics():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM resources")
    total_resources = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM risks")
    total_risks = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM risks
        WHERE severity = 'Critical'
        AND status = 'Open'
    """)
    critical = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM risks
        WHERE severity = 'High'
        AND status = 'Open'
    """)
    high = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM risks
        WHERE severity = 'Medium'
        AND status = 'Open'
    """)
    medium = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM risks
        WHERE severity = 'Low'
        AND status = 'Open'
    """)
    low = cursor.fetchone()[0]

    connection.close()

    return {
        "total_resources": total_resources,
        "total_risks": total_risks,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }


# ---------------------------------------------------------
# RUN INITIALIZATION
# ---------------------------------------------------------

if __name__ == "__main__":

    initialize_database()

    print("----------------------------------------")
    print("CloudGuard AI Database")
    print("----------------------------------------")
    print("Database initialized successfully.")
    print(f"Database location: {DATABASE_PATH}")
    print("----------------------------------------")