import subprocess
from .db_handler import DatabaseManager
from .generate_report import ReportManager

from .report_config import EMAIL_SCRIPT, BACKUP_SCRIPT, COMPILE_PDF, RUNNING


def send_report():
    """Send the report via mail."""
    try:
        subprocess.run([EMAIL_SCRIPT], check=True)
        print("Report emailed")
    except subprocess.CalledProcessError as e:
        print(f"Email failed: {e}")


def backup_report():
    """Backup the report to MinIO."""
    try:
        subprocess.run([BACKUP_SCRIPT], check=True)
        print("Report emailed")
    except subprocess.CalledProcessError as e:
        print(f"Email failed: {e}")


if __name__ == "__main__":
    """Work in the pipeline mentioned in the README."""
    # open database connection
    db = DatabaseManager()
    try:
        # 1. Update the DB summary table
        db.update_summary_metrics(running=RUNNING)
        print("Summary table updated")

        # 2. Generate the report
        summary_data = db.fetch_latest_summary_for_nation()
        report = ReportManager(summary_data, db)
        report.render_supervisor(compile_pdf=COMPILE_PDF)  # Supervisor Report
        report.render_admin(compile_pdf=COMPILE_PDF)  # Admin report

        # 3. Send the report in mail
        #send_report()

        # 4. backup the report
        # backup_report()

        # close database connection
    finally:
        db.close()
