from click.testing import CliRunner

from pvss.cli import cli

def test_cli() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("dhparams.pem", "wt") as fp:
            fp.writelines([
                "-----BEGIN DH PARAMETERS-----\n",
                "MA4CCQDxE8ZyVvUx0wIBAg==\n",
                "-----END DH PARAMETERS-----\n",
            ])
        runner.invoke(cli, ['data', 'genparams', 'qr', "dhparams.pem"], catch_exceptions=False, color=True)
    with runner.isolated_filesystem():
        for cmd in [
            ["genparams", "rst255"],
            ["genuser", "Alice", "alice.key"],
            ["genuser", "Boris", "boris.key"],
            ["genuser", "Chris", "chris.key"],
            ["splitsecret", "2", "secret0.der"],
            ["genreceiver", "recv.key"],
            ["reencrypt", "boris.key"],
            ["reencrypt", "alice.key"],
            ["reconstruct", "recv.key", "secret1.der"],
        ]:
            runner.invoke(cli, ['data'] + cmd, catch_exceptions=False, color=True)
