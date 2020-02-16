"""
Command line utility for PVSS
"""

from __future__ import annotations

import logging
from contextlib import suppress
from io import BufferedIOBase
from os import getcwd, umask
from pathlib import Path
from random import randrange

import click

from .pvss import Pvss, PublicKey


def pvss_from_datadir(datadir: Path) -> Pvss:
    """
    Read in the data directory; create it if it doesn't exist.
    """

    pvss = Pvss()

    # Read files in order. If any is missing (e.g. not generated yet), that's not a problem.
    with suppress(FileNotFoundError):
        pvss.set_params((datadir / "parameters").read_bytes())
        logging.info("Loaded parameters")

        for path in (datadir / "users").iterdir():
            pub = pvss.add_user_public_key(path.read_bytes())
            logging.info(f"Loaded user public key {path} ({pub.name})")

        pvss.set_shares((datadir / "shares").read_bytes())
        logging.info("Loaded shares")

        pvss.set_receiver_public_key((datadir / "receiver").read_bytes())
        logging.info("Loaded receiver public key")

        for path in (datadir / "reencrypted").iterdir():
            reenc_share = pvss.add_reencrypted_share(path.read_bytes())
            logging.info(f"Loaded reencrypted share {path} ({reenc_share.share.pub.name})")

    return pvss


def write_private(path: Path, contents: bytes) -> None:
    prev = umask(0o077)
    try:
        with path.open("xb") as fp:
            fp.write(contents)
    finally:
        umask(prev)


def write_public(path: Path, contents: bytes) -> None:
    with path.open("xb") as fp:
        fp.write(contents)


def write_public_random(path: Path, contents: bytes) -> None:
    path.mkdir(exist_ok=True)
    for __ in range(10):
        name = format(randrange(2 ** 32), "08x")
        with suppress(FileExistsError), (path / name).open("xb") as fp:
            fp.write(contents)
            return
    raise FileExistsError("Cannot find unused random name")  # pragma: no cover


@click.group()
@click.argument(
    "datadir",
    type=click.Path(file_okay=False, resolve_path=True),
    callback=lambda ctx, param, value: Path(value),
    required=True,
    metavar="DATADIR",
)
@click.pass_context
def cli(ctx: click.Context, datadir: Path) -> None:
    """
    Publicly Verifiable Secret Splitting

    PVSS is a cryptographic protocol to split a random secret amongst N
    users and T of those can later cooperate to reconstruct the secret.

    All messages can be exchanged over public channels and can be verified by
    everyone to be correct.

    https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing

    DATADIR needs to point at a directory which contains all the public
    messages that are being exchanged. If the directory does not exist, it is
    created.

    All sub commands read and verify all messages from that directory and add
    their own messages.
    """
    ctx.obj = datadir

    logging.basicConfig(level=logging.INFO)


@cli.group()
def genparams() -> None:
    """
    Generate system parameters.

    They are written to {datadir}/parameters.
    """


@genparams.command("qr")
@click.argument("dhparams", metavar="DHPARAMS", type=click.File(mode="rb"))
@click.pass_context
def genparams_qr(ctx: click.Context, dhparams: BufferedIOBase) -> None:
    """
    Generate QR system parameters.

    DHPARAMS is a file with diffie hellman parameters as created by
    `openssl dhparam 4096`, either DER or PEM format.

    PVSS works with almost any bit length, but the security level depends on it.
    4096 should be a sane choice.
    """
    from .qr import create_qr_params

    pvss = pvss_from_datadir(ctx.obj)
    params = create_qr_params(pvss, dhparams.read())

    ctx.obj.mkdir(exist_ok=True)
    write_public(ctx.obj / "parameters", params)


@genparams.command("rst255")
@click.pass_context
def genparams_rst255(ctx: click.Context) -> None:
    """
    Generate Ristretto255 system parameters.

    For details about Ristretto255, refer to https://ristretto.group/
    """
    from .ristretto_255 import create_ristretto_255_parameters

    pvss = pvss_from_datadir(ctx.obj)
    params = create_ristretto_255_parameters(pvss)

    ctx.obj.mkdir(exist_ok=True)
    write_public(ctx.obj / "parameters", params)


@cli.command()
@click.argument("name", metavar="NAME")
@click.argument(
    "keyfile",
    metavar="KEYFILE",
    type=click.Path(dir_okay=False, resolve_path=True),
    callback=lambda ctx, param, value: Path(value),
)
@click.pass_context
def genuser(ctx: click.Context, name: str, keyfile: Path) -> None:
    """
    Generate keypair for a new user.

    The NAME of the key owner is stored in the public key.
    The public key is written to {datadir}/users/ with random filename.

    The private key is written to KEYFILE.
    """
    pvss = pvss_from_datadir(ctx.obj)
    priv, pub = pvss.create_user_keypair(name)
    write_private(keyfile, priv)
    write_public_random(ctx.obj / "users", pub)


@cli.command()
@click.argument(
    "keyfile",
    metavar="KEYFILE",
    type=click.Path(dir_okay=False, resolve_path=True),
    callback=lambda ctx, param, value: Path(value),
)
@click.option("--name", help="Name of receiver", default="receiver")
@click.pass_context
def genreceiver(ctx: click.Context, keyfile: Path, name: str) -> None:
    """
    Generate keypair for the receiver.

    The private key is written to KEYFILE, the public key is written to {datadir}/receiver.
    """
    pvss = pvss_from_datadir(ctx.obj)
    priv, pub = pvss.create_receiver_keypair(name)
    write_private(keyfile, priv)
    write_public(ctx.obj / "receiver", pub)


@cli.command()
@click.argument("min_shares", metavar="MIN_SHARES", type=int)
@click.argument(
    "secretfile",
    metavar="SECRETFILE",
    type=click.Path(dir_okay=False, resolve_path=True),
    callback=lambda ctx, param, value: Path(value),
)
@click.pass_context
def splitsecret(ctx: click.Context, min_shares: int, secretfile: Path) -> None:
    """
    Generate and split random secret.

    This generates a new random secret and writes it into SECRETFILE.
    The secret is split it into multiple shares, each encrypted with a user's public key.
    Those shared are written to {datadir}/shares.

    At least MIN_SHARES users need to cooperate to reconstruct the secret.
    """
    pvss = pvss_from_datadir(ctx.obj)
    secret, shares = pvss.share_secret(min_shares)
    write_private(secretfile, secret)
    write_public(ctx.obj / "shares", shares)


@cli.command()
@click.argument("keyfile", metavar="KEYFILE", type=click.File(mode="rb"))
@click.pass_context
def reencrypt(ctx: click.Context, keyfile: BufferedIOBase) -> None:
    """
    Re-encrypt share with receiver key.

    Decrypt a user's share with their private key KEYFILE and re-encrypt it with the receiver's
    public key.  The re-encrypted share is written to {datadir}/reencrypted/{username}.
    """
    pvss = pvss_from_datadir(ctx.obj)
    reencrypted_share = pvss.reencrypt_share(keyfile.read())
    write_public_random(ctx.obj / "reencrypted", reencrypted_share)


@cli.command()
@click.argument("keyfile", metavar="KEYFILE", type=click.File(mode="rb"))
@click.argument(
    "secretfile",
    metavar="SECRETFILE",
    type=click.Path(dir_okay=False, resolve_path=True),
    callback=lambda ctx, param, value: Path(value),
)
@click.pass_context
def reconstruct(ctx: click.Context, keyfile: BufferedIOBase, secretfile: Path) -> None:
    """
    Reconstruct the secret.

    Decrypt re-encrypted shares with the receiver's private key KEYFILE and
    join the shares to reconstruct the secret.  It is written into SECRETFILE.
    """
    pvss = pvss_from_datadir(ctx.obj)
    secret = pvss.reconstruct_secret(keyfile.read())
    write_private(secretfile, secret)
