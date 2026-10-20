"""Management commands:  flask --app webrecon <command>"""
import click

from . import audit, auth


def register(app):
    db = app.extensions["webrecon"].db

    @app.cli.command("create-user")
    @click.argument("username")
    @click.option("--role", default="user", type=click.Choice(["user", "admin"]))
    @click.password_option(confirmation_prompt=True)
    def create_user(username, role, password):
        """Create a user (passwords are prompted, never passed on the command line)."""
        try:
            auth.create_user(db, username, password, role)
        except auth.AuthError as exc:
            raise click.ClickException(str(exc))
        click.echo(f"Created {role} '{username}'.")

    @app.cli.command("create-token")
    @click.argument("username")
    @click.option("--name", default="cli")
    def create_token(username, name):
        """Create an API token (printed once)."""
        row = db.one("SELECT id FROM users WHERE username = ?", (username,))
        if row is None:
            raise click.ClickException("No such user.")
        click.echo(auth.create_token(db, row["id"], name))

    @app.cli.command("audit")
    @click.option("--limit", default=50)
    def show_audit(limit):
        """Print the latest audit log entries."""
        for e in reversed(audit.recent(db, limit)):
            click.echo(f"{e['ts']}  {e['username'] or '-':<12} {e['ip'] or '-':<15} {e['action']:<18} {e['detail'] or ''}")
