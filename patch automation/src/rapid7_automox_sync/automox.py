import uuid
from pathlib import Path
from typing import Any

from .http import HttpClient

AUTOMOX_HOST = "console.automox.com"


class AutomoxClient:
    def __init__(
        self,
        api_key: str,
        organization_id: int,
        http: HttpClient | None = None,
    ) -> None:
        if organization_id <= 0:
            raise ValueError("Automox organization ID must be a positive integer")
        self.organization_id = organization_id
        self.http = http or HttpClient(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "rapid7-automox-sync/0.1.0",
            },
            allowed_hosts={AUTOMOX_HOST},
        )

    def upload_rapid7_csv(self, csv_path: Path) -> dict[str, Any]:
        url = (
            f"https://{AUTOMOX_HOST}/api/orgs/"
            f"{self.organization_id}/remediations/action-sets/upload"
        )
        boundary = f"----rapid7-automox-{uuid.uuid4().hex}"
        body = _multipart_body(boundary, csv_path)
        return self.http.request_json(
            "POST",
            url,
            params={"source": "rapid7"},
            body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            timeout=300,
        )


def _multipart_body(boundary: str, csv_path: Path) -> bytes:
    filename = _safe_filename(csv_path.name)
    marker = f"--{boundary}\r\n".encode()
    return b"".join(
        [
            marker,
            b'Content-Disposition: form-data; name="format"\r\n\r\n',
            b"rapid7\r\n",
            marker,
            (
                'Content-Disposition: form-data; name="file"; '
                f'filename="{filename}"\r\n'
            ).encode(),
            b"Content-Type: text/csv\r\n\r\n",
            csv_path.read_bytes(),
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )


def _safe_filename(name: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return cleaned or "rapid7-findings.csv"
