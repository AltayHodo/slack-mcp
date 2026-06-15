#!/usr/bin/env python3
"""
Interactive helper: update the Slack app credentials in .env.tenants for the
'internal' and 'fellow-facing' tenants without echoing secrets to the shell.

For each field, the current value (if any) is shown and kept if you just press
Enter — so re-running to add/change one field doesn't require re-typing the
others. Captures the optional Slack team_id (T…) used to pin the OAuth flow to
a specific workspace. Preserves SLACK_EXTERNAL_URL and SLACK_MCP_PORT. Run:
    python3 set-tenant-creds.py
"""
import json
import pathlib
from getpass import getpass

ENV = pathlib.Path(".env.tenants")
TENANT_IDS = ["internal", "fellow-facing"]


# Keys this script owns and rewrites; every other line is preserved verbatim.
MANAGED_PREFIXES = ("SLACK_EXTERNAL_URL=", "SLACK_MCP_PORT=", "SLACK_TENANTS=")


def read_existing():
    """Return (external_url, port, {tenant_id: entry_dict}, other_lines).

    `other_lines` holds every line this script does not manage (e.g.
    SLACK_MCP_ENCRYPTION_KEY, SLACK_MCP_DB_PATH, comments) so they survive a
    rewrite — dropping the encryption key would orphan the existing database.
    """
    external_url, port = "", "8001"
    by_id = {}
    other_lines = []
    if ENV.exists():
        for line in ENV.read_text().splitlines():
            if line.startswith("SLACK_EXTERNAL_URL="):
                external_url = line.split("=", 1)[1].strip()
            elif line.startswith("SLACK_MCP_PORT="):
                port = line.split("=", 1)[1].strip()
            elif line.startswith("SLACK_TENANTS="):
                raw = line.split("=", 1)[1].strip().strip("'").strip('"')
                try:
                    for t in json.loads(raw):
                        if t.get("id"):
                            by_id[t["id"]] = t
                except json.JSONDecodeError:
                    pass
            elif line.strip():
                other_lines.append(line)
    return external_url, port, by_id, other_lines


def _mask(val, keep=12):
    if not val:
        return ""
    return val if len(val) <= keep else val[:keep] + "…"


def prompt_keep(label, current):
    """Prompt for a non-secret value, keeping `current` if the user hits Enter."""
    shown = f" [{_mask(current)}]" if current else ""
    val = input(f"{label}{shown}: ").strip()
    return val if val else (current or "")


def prompt_secret_keep(label, current):
    """Prompt for a secret (hidden), keeping `current` if the user hits Enter."""
    hint = " [keep existing]" if current else ""
    val = getpass(f"{label} (hidden){hint}: ").strip()
    return val if val else (current or "")


def main():
    external_url, port, existing, other_lines = read_existing()
    if not external_url:
        external_url = input("SLACK_EXTERNAL_URL (tunnel/host, no trailing slash): ").strip()

    print(f"\nUsing SLACK_EXTERNAL_URL={external_url}")
    print("(press Enter at any prompt to keep the current value)\n")

    tenants = []
    for tid in TENANT_IDS:
        prev = existing.get(tid, {})
        print(f"--- tenant '{tid}' ---")
        cid = prompt_keep(f"  {tid} Client ID", prev.get("client_id"))
        sec = prompt_secret_keep(f"  {tid} Client Secret", prev.get("client_secret"))
        team = prompt_keep(f"  {tid} Team ID (T…, optional)", prev.get("team_id"))
        entry = {"id": tid, "client_id": cid, "client_secret": sec}
        if team:
            entry["team_id"] = team
        tenants.append(entry)
        print()

    content = (
        f"SLACK_EXTERNAL_URL={external_url}\n"
        f"SLACK_MCP_PORT={port}\n"
        f"SLACK_TENANTS='{json.dumps(tenants)}'\n"
    )
    # Re-emit preserved lines (encryption key, db path, comments) so a routine
    # credential update never strips them.
    if other_lines:
        content += "\n" + "\n".join(other_lines) + "\n"
    ENV.write_text(content)

    print(f"Wrote {ENV} with {len(tenants)} tenants.")
    for t in tenants:
        cid, sec, team = t["client_id"], t["client_secret"], t.get("team_id")
        ok = "OK" if (cid and sec) else "MISSING VALUES"
        team_str = team if team else "— (no team pin)"
        print(f"  {t['id']}: client_id={_mask(cid) or '—'}  secret={'set' if sec else '—'}  team={team_str}  [{ok}]")


if __name__ == "__main__":
    main()
