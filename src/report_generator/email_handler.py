#!/usr/bin/env python3
import os
import sys
import smtplib
from glob import glob
from email.message import EmailMessage


def main():
    """
    Entry point for sending the supervisor report.

    Loads configuration from environment variables, locates the latest PDF
    file for the given NATION, composes a multipart email, and sends it via SMTP.

    Raises:
        SystemExit: if required environment variables are missing,
                    if no PDF is found, or if SMTP fails.
    """
    # Load settings
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 0))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    EMAIL_FROM = os.getenv("EMAIL_FROM")
    EMAIL_TO = os.getenv("EMAIL_TO")
    NATION = os.getenv("NATION")

    # Sanity check
    for var in ("SMTP_SERVER", "SMTP_PORT", "EMAIL_FROM", "EMAIL_TO", "NATION"):
        if not locals()[var]:
            print(f"ERROR: Missing env var {var}", file=sys.stderr)
            sys.exit(1)

    # Pick the newest PDF
    here = os.path.dirname(os.path.abspath(__file__))
    rpt_dir = os.path.join(here, "reports", NATION, "supervisor")
    pdfs = sorted(
        glob(os.path.join(rpt_dir, "*.pdf")),
        key=os.path.getmtime,
        reverse=True
    )
    if not pdfs:
        print(f"ERROR: no PDF in {rpt_dir}", file=sys.stderr)
        sys.exit(1)
    pdf_path = pdfs[0]

    # Build email
    msg = EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg["Subject"] = f"ScanICE Supervisor Report for {NATION}"
    msg.set_content(f"""
Hello,

Attached is the latest supervisor report for {NATION}.

Regards,
Team Völva
""")

    with open(pdf_path, "rb") as f:
        data = f.read()
    msg.add_attachment(
        data,
        maintype="application",
        subtype="pdf",
        filename=os.path.basename(pdf_path)
    )

    # Send via SMTP
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.set_debuglevel(1)
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[email_handler] Sent {pdf_path}")
    except Exception as e:
        print(f"[email_handler] Failed to send: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
