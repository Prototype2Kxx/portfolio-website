"""
Deploy portfolio site to IONOS via SFTP.
Uploads all website files, skipping developer/git files.

Required environment variables (GitHub Secrets):
  FTP_HOST  — IONOS SFTP hostname
  FTP_USER  — IONOS FTP username
  FTP_PASS  — IONOS FTP password
"""

import os
import sys
import paramiko
from pathlib import Path

# Files/folders that should NOT be uploaded to the live server
EXCLUDE = {
    '.git',
    '.github',
    'docs',
    'CLAUDE.md',
    '.gitignore',
    '__pycache__',
}


def sftp_mkdir_p(sftp, remote_dir: str):
    """Create a remote directory and all its parents (like mkdir -p)."""
    parts = remote_dir.replace('\\', '/').split('/')
    path = ''
    for part in parts:
        if not part:
            continue
        path = f"{path}/{part}" if path else part
        try:
            sftp.mkdir(path)
        except OSError:
            pass  # Already exists


def deploy():
    host     = os.environ['FTP_HOST']
    user     = os.environ['FTP_USER']
    password = os.environ['FTP_PASS']

    # Repo root is two levels up from this script (.github/scripts/)
    local_base = Path(__file__).resolve().parent.parent.parent

    print(f"Connecting to {host}…")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=22, username=user, password=password, timeout=30)
    sftp = client.open_sftp()

    uploaded = 0
    skipped  = 0
    errors   = 0

    for local_path in sorted(local_base.rglob('*')):
        if not local_path.is_file():
            continue

        # Skip anything inside an excluded directory
        rel_parts = local_path.relative_to(local_base).parts
        if any(part in EXCLUDE for part in rel_parts):
            skipped += 1
            continue

        rel_path    = local_path.relative_to(local_base)
        remote_path = str(rel_path).replace('\\', '/')
        remote_dir  = '/'.join(remote_path.split('/')[:-1])

        # Ensure the remote directory exists
        if remote_dir:
            sftp_mkdir_p(sftp, remote_dir)

        try:
            sftp.put(str(local_path), remote_path)
            print(f"  ✓ {remote_path}")
            uploaded += 1
        except Exception as e:
            print(f"  ✗ {remote_path} — {e}")
            errors += 1

    sftp.close()
    client.close()

    print(f"\n{'─'*50}")
    print(f"Uploaded : {uploaded} files")
    print(f"Skipped  : {skipped} files")
    print(f"Errors   : {errors} files")

    if errors:
        print("Deployment finished with errors.")
        sys.exit(1)
    else:
        print("Deployment complete ✓")


if __name__ == '__main__':
    deploy()
