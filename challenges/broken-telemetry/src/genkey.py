#!/usr/bin/env python3
#
# Generate chall ED25519 private/public key pair for patch signing
#

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def create_keys(privkey_path: Path, pubkey_path: Path):
	private_key = ed25519.Ed25519PrivateKey.generate()
	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)

	with privkey_path.open('wb') as f:
		f.write(private_pem)

	public_key = private_key.public_key()
	public_raw = public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw
	)

	with pubkey_path.open('wb') as f:
		f.write(public_raw)


if __name__ == '__main__':
	mydir = Path(__file__).parent
	create_keys(mydir / 'build/privkey.pem', mydir / 'build/pubkey.bin')
	create_keys(mydir / 'build/player_privkey.pem', mydir / 'build/player_pubkey.bin')
