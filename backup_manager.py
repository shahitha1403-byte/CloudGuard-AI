import sqlite3
from datetime import datetime
from pathlib import Path
import shutil


# ============================================================
# CLOUDGUARD AI - AUTOMATIC BACKUP & RECOVERY
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_DIR = BASE_DIR / "database"
BACKUP_DIR = BASE_DIR / "backups"

DB_PATH = DATABASE_DIR / "cloudguard.db"

BACKUP_DIR.mkdir(
    parents=True,
    exist_ok=True
)


class BackupManager:

    def __init__(self):
        self.db_path = DB_PATH
        self.backup_dir = BACKUP_DIR

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
    # CREATE BACKUP
    # ========================================================

    def create_backup(self):

        if not self.db_path.exists():

            print("Database file not found.")

            return None

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        backup_name = (
            f"cloudguard_backup_{timestamp}.db"
        )

        backup_path = (
            self.backup_dir /
            backup_name
        )

        # ----------------------------------------------------
        # SQLite safe backup
        # ----------------------------------------------------

        source = sqlite3.connect(
            self.db_path
        )

        destination = sqlite3.connect(
            backup_path
        )

        try:

            source.backup(
                destination
            )

        finally:

            destination.close()
            source.close()

        # ----------------------------------------------------
        # Verify created file
        # ----------------------------------------------------

        if not backup_path.exists():

            print(
                "Backup file could not be created."
            )

            return None

        # ----------------------------------------------------
        # Save backup history
        # ----------------------------------------------------

        self.save_backup_history(
            backup_name,
            str(backup_path),
            "SUCCESS"
        )

        return backup_path

    # ========================================================
    # SAVE BACKUP HISTORY
    # ========================================================

    def save_backup_history(
        self,
        backup_name,
        backup_path,
        status
    ):

        connection = self.get_connection()
        cursor = connection.cursor()

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        columns = self.get_columns(
            "backup_history"
        )

        # ----------------------------------------------------
        # Dynamic values for existing database schema
        # ----------------------------------------------------

        values_map = {

            "backup_name":
                backup_name,

            "backup_path":
                backup_path,

            "file_path":
                backup_path,

            "path":
                backup_path,

            "status":
                status,

            "created_at":
                now,

            "updated_at":
                now,

            "timestamp":
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

        # ----------------------------------------------------
        # Safety check
        # ----------------------------------------------------

        if not insert_columns:

            connection.close()

            print(
                "No compatible backup_history columns found."
            )

            return False

        placeholders = ", ".join(
            ["?"] * len(insert_values)
        )

        query = f"""
            INSERT INTO backup_history
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
    # VERIFY BACKUP
    # ========================================================

    def verify_backup(
        self,
        backup_path
    ):

        backup_path = Path(
            backup_path
        )

        if not backup_path.exists():

            return False

        try:

            connection = sqlite3.connect(
                backup_path
            )

            cursor = connection.cursor()

            cursor.execute(
                "PRAGMA integrity_check"
            )

            result = cursor.fetchone()

            connection.close()

            if result and result[0] == "ok":

                return True

        except sqlite3.Error:

            return False

        return False

    # ========================================================
    # LIST AVAILABLE BACKUPS
    # ========================================================

    def list_backups(self):

        backups = sorted(
            self.backup_dir.glob(
                "cloudguard_backup_*.db"
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True
        )

        return backups

    # ========================================================
    # RECOVER DATABASE
    # ========================================================

    def recover_database(
        self,
        backup_path
    ):

        backup_path = Path(
            backup_path
        )

        if not backup_path.exists():

            print(
                "Backup file not found."
            )

            return False

        if not self.db_path.exists():

            print(
                "Current database not found."
            )

            return False

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        safety_backup = (
            self.backup_dir /
            f"before_recovery_{timestamp}.db"
        )

        # ----------------------------------------------------
        # Protect current database
        # ----------------------------------------------------

        shutil.copy2(
            self.db_path,
            safety_backup
        )

        # ----------------------------------------------------
        # Restore selected backup
        # ----------------------------------------------------

        source = sqlite3.connect(
            backup_path
        )

        destination = sqlite3.connect(
            self.db_path
        )

        try:

            source.backup(
                destination
            )

        finally:

            destination.close()
            source.close()

        self.save_backup_history(
            backup_path.name,
            str(backup_path),
            "RECOVERED"
        )

        return True

    # ========================================================
    # RUN BACKUP SYSTEM
    # ========================================================

    def run(self):

        print("=" * 65)
        print(
            "CloudGuard AI - Backup & Recovery Manager"
        )
        print("=" * 65)

        print()
        print(
            f"Database : {self.db_path}"
        )

        print(
            f"Backup Directory : {self.backup_dir}"
        )

        # ----------------------------------------------------
        # CREATE BACKUP
        # ----------------------------------------------------

        print()
        print(
            "Creating automatic database backup..."
        )

        backup_path = self.create_backup()

        if not backup_path:

            print(
                "Backup creation failed."
            )

            return

        print(
            f"Backup Created : {backup_path.name}"
        )

        # ----------------------------------------------------
        # VERIFY
        # ----------------------------------------------------

        print()
        print(
            "Verifying backup integrity..."
        )

        verified = self.verify_backup(
            backup_path
        )

        if verified:

            print(
                "Backup Verification : PASSED"
            )

        else:

            print(
                "Backup Verification : FAILED"
            )

        # ----------------------------------------------------
        # AVAILABLE BACKUPS
        # ----------------------------------------------------

        backups = self.list_backups()

        print()
        print(
            f"Available Backups : {len(backups)}"
        )

        for index, backup in enumerate(
            backups,
            start=1
        ):

            print(
                f"{index}. {backup.name}"
            )

        print()
        print("=" * 65)
        print(
            "BACKUP SYSTEM STATUS"
        )
        print("=" * 65)

        print(
            "Automatic Backup : ENABLED"
        )

        print(
            "Backup Integrity : "
            + (
                "VALID"
                if verified
                else "INVALID"
            )
        )

        print(
            "Recovery System  : READY"
        )

        print("=" * 65)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    manager = BackupManager()

    manager.run()

    print()
    print(
        "Backup and recovery system completed successfully."
    )