import os
from langchain_core.tools import tool

OUTBOX = []

def reset_outbox() -> None:
    """Clear simulation outbox data between evaluation loops."""
    OUTBOX.clear()

@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Simulate emailing execution workflows by appending actions to an outbox."""
    email_payload = {"to": to, "subject": subject, "body": body}
    OUTBOX.append(email_payload)

    print(
        f"[EMAIL ACTION EXECUTION]\n"
        f"  To:      {to}\n"
        f"  Subject: {subject}\n"
        f"  Body:    {body}\n"
    )
    return f"Success: Email queued and sent to {to}"
