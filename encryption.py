import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "secret.key"


def load_key():

    if not os.path.exists(KEY_FILE):

        key = AESGCM.generate_key(bit_length=256)

        with open(KEY_FILE, "wb") as f:
            f.write(key)

    with open(KEY_FILE, "rb") as f:
        return f.read()


KEY = load_key()


def encrypt_file(input_file, output_file):

    aesgcm = AESGCM(KEY)

    nonce = os.urandom(12)

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(output_file, "wb") as f:
        f.write(nonce + encrypted)


def decrypt_file(input_file, output_file):

    aesgcm = AESGCM(KEY)

    with open(input_file, "rb") as f:
        file_data = f.read()

    nonce = file_data[:12]

    encrypted = file_data[12:]

    decrypted = aesgcm.decrypt(
        nonce,
        encrypted,
        None
    )

    with open(output_file, "wb") as f:
        f.write(decrypted)