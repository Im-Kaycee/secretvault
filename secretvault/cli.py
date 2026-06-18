"""
The `vault` command. Wires crypto, storage, and audit together.

Usage:
    vault put <path> <value>
    vault get <path>
    vault list
    vault delete <path>
    vault rotate-master-key
    vault audit-log
    vault verify
"""

import sys
import datetime
import click
from cryptography.fernet import InvalidToken


from secretvault import crypto, storage, audit


def get_kek() -> bytes:
    return crypto.load_or_create_kek()


def get_conn():
    conn = storage.get_connection()
    storage.init_db(conn)
    return conn


@click.group()
def cli():
    """A local, encrypted secrets vault with a tamper-evident audit log."""
    pass


@cli.command()
@click.argument("path")
@click.argument("value")
def put(path, value):
    """Store a secret at PATH with VALUE."""
    conn = get_conn()
    kek = get_kek()

    ciphertext, wrapped_dek = crypto.seal_secret(value, kek)
    storage.put_secret(conn, path, ciphertext, wrapped_dek)
    audit.log_action(conn, "PUT", path)

    click.echo(f"Stored secret at '{path}'.")


@cli.command()
@click.argument("path")
def get(path):
    """Retrieve the secret stored at PATH."""
    conn = get_conn()
    kek = get_kek()

    result = storage.get_secret(conn, path)
    if result is None:
        click.echo(f"No secret found at '{path}'.", err=True)
        sys.exit(1)

    ciphertext, wrapped_dek = result
    try:
        plaintext = crypto.open_secret(ciphertext, wrapped_dek, kek)
    except InvalidToken:
        click.echo(
            "Decryption failed - VAULT_MASTER_KEY is wrong or out of date "
            "(maybe the key was rotated and your env var wasn't updated?).",
            err=True,
        )
        sys.exit(1)

    audit.log_action(conn, "GET", path)
    click.echo(plaintext)


@cli.command(name="list")
def list_cmd():
    """List all secret paths (not their values)."""
    conn = get_conn()
    paths = storage.list_secrets(conn)

    if not paths:
        click.echo("No secrets stored yet.")
        return

    for p in paths:
        click.echo(p)


@cli.command()
@click.argument("path")
def delete(path):
    """Delete the secret stored at PATH."""
    conn = get_conn()
    deleted = storage.delete_secret(conn, path)

    if not deleted:
        click.echo(f"No secret found at '{path}'.", err=True)
        sys.exit(1)

    audit.log_action(conn, "DELETE", path)
    click.echo(f"Deleted secret at '{path}'.")


@cli.command(name="audit-log")
def audit_log_cmd():
    """Show the full audit log."""
    conn = get_conn()
    entries = audit.get_log_entries(conn)

    if not entries:
        click.echo("No audit log entries yet.")
        return

    for entry_id, timestamp, action, path, prev_hash, this_hash in entries:
        ts = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"[{entry_id:4}] {ts}  {action:6}  {path:30}  hash={this_hash[:12]}...")


@cli.command()
def verify():
    """Verify the audit log hasn't been tampered with."""
    conn = get_conn()
    is_valid, error = audit.verify_chain(conn)

    if is_valid:
        click.echo("Audit log verified - no tampering detected.")
    else:
        click.echo(f"TAMPERING DETECTED: {error}", err=True)
        sys.exit(1)


@cli.command(name="rotate-master-key")
def rotate_master_key():
    """
    Rotate the master key (KEK). Re-wraps every secret's DEK with a new
    KEK, without touching the secrets' encrypted values at all.
    """
    conn = get_conn()
    old_kek = get_kek()
    new_kek = crypto.generate_kek()

    all_deks = storage.get_all_wrapped_deks(conn)
    click.echo(f"Re-wrapping {len(all_deks)} secret(s) with new master key...")

    for path, wrapped_dek in all_deks:
        new_wrapped_dek = crypto.rewrap_dek(wrapped_dek, old_kek, new_kek)
        storage.update_wrapped_dek(conn, path, new_wrapped_dek)
        audit.log_action(conn, "ROTATE", path)

    click.echo()
    click.echo("=" * 70)
    click.echo("ROTATION COMPLETE. Update your master key env var to:")
    click.echo()
    click.echo(f"  export VAULT_MASTER_KEY={new_kek.decode()}")
    click.echo()
    click.echo("The OLD key will no longer work after you replace it.")
    click.echo("=" * 70)


if __name__ == "__main__":
    cli()