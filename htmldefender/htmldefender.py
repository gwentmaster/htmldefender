#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2021-02-06 13:44:52
# @Author  : gwentmaster(1950251906@qq.com)
# I regret in my life


import argparse
import hmac
import os
import shutil
from base64 import b64encode
from hashlib import sha256
from os import urandom
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import pad


def encrypt(content: bytes, password: str) -> str:
    """
    Encrypt html content, act like `staticrypt`.

    Args:
        content: html content bytes
        password: password to encrypt and decrypt

    Returns:
        The encrypted contend
    """

    salt = urandom(16)
    iv = urandom(16)
    key = PBKDF2(
        password=password,
        salt=salt,
        dkLen=32,
        count=1000
    )
    cryptor = AES.new(key, AES.MODE_CBC, iv)

    pkcs7_content = pad(content, AES.block_size)

    aes_encrypted_bytes = b64encode(
        cryptor.encrypt(pkcs7_content)
    )

    aes_encrypted_content = (
        salt.hex()
        + iv.hex()
        + aes_encrypted_bytes.decode("utf-8")
    )

    hmac_signature = hmac.new(
        key=sha256(password.encode("utf-8")).hexdigest().encode("utf-8"),
        msg=aes_encrypted_content.encode("utf-8"),
        digestmod=sha256
    ).hexdigest()

    return hmac_signature + aes_encrypted_content


def get_template() -> str:
    """read the the template file

    Returns:
        the template string
    """

    template_path = Path(__file__).parent / Path("password_template.html")
    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()
    return template


TEMPLATE = get_template()


def render(encrypted_msg: str) -> str:
    """fill the template with the encrypted message

    Args:
        encrypted_msg: encrypted message

    Returns:
        the encrypted html content to replace the raw file
    """

    start = TEMPLATE.find("{encrypted}")
    end = start + len("{encrypted}")
    return TEMPLATE[:start] + encrypted_msg + TEMPLATE[end:]


def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "password",
        type=str,
        help="the password to encrypt and decrypt"
    )
    parser.add_argument(
        "directory",
        type=str,
        help="the directory of html files to encrypt"
    )
    parser.add_argument(
        "--backup",
        type=bool,
        default=False,
        help="whether to backup the raw html files"
    )
    return parser.parse_args()


def backup_html(
    base_dir: Path,
    file_name: str,
    backup_dir: Path,
    component_lstrip: int
) -> None:
    """backup a html file

    Args:
        base_dir: the base directory the file lays
        file_name: the html file name, with `.html` suffix
        backup_dir: the root directory of backup files
        component_lstrip: the number indicates how many components
                          are useless in parts of `base_dir`
    """

    target_dir = backup_dir.joinpath(*base_dir.parts[component_lstrip:])
    os.makedirs(target_dir, exist_ok=True)

    shutil.copy(base_dir / file_name, target_dir / file_name)


def encrypt_html_file(file: Path, password: str) -> None:
    """encrypt a html file

    Args:
        file: the html file path
        password: the password to encrypt and decrypt
    """

    with open(file, "rb+") as f:
        encrypted_content = encrypt(content=f.read(), password=password)
        f.seek(0)
        f.truncate()
        f.write(render(encrypted_content).encode("utf-8"))


def main():

    argument = parse_args()
    password = argument.password  # type: str
    directory = Path(argument.directory)  # type: Path
    backup = argument.backup  # type: bool

    if not directory.is_dir():
        print("not a valid directory")
        return

    if backup is True:
        backup_dir = (
            directory.parent / Path(f"{directory.name}.htmldefender_backup")
        )
        os.makedirs(backup_dir, exist_ok=True)

    component_length = len(directory.parts)
    for base_dir, dirs, files in os.walk(directory):
        base_dir = Path(base_dir)
        for file in files:
            if not file.endswith(".html"):
                continue
            if backup is True:
                backup_html(
                    base_dir=base_dir,
                    file_name=file,
                    backup_dir=backup_dir,
                    component_lstrip=component_length
                )
            encrypt_html_file(
                file=(base_dir / file),
                password=password
            )


if __name__ == "__main__":

    main()
