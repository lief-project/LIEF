#!/usr/bin/env python
"""Verify Authenticode signatures and inspect certificates in PE binaries.

Checks whether a PE binary has a valid Authenticode signature, computes
authentihash digests, and lists all certificates in the signature chain.

Example:

    $ python pe_authenticode.py driver.sys
    Authenticode Report: driver.sys
    ================================================
      Signature Present:          Yes
      Verification:               OK
      Authentihash (MD5):         a1:b2:c3:...
      Authentihash (SHA-256):     de:ad:be:...

      Certificate Chain:
        [0] Subject: CN=Microsoft Windows, O=Microsoft Corporation
            Issuer:  CN=Microsoft Windows Verification PCA
            Serial:  61:01:c6:c1:...
            Valid:   2008-10-22 -> 2010-01-22
        ...
"""

import sys
import lief


def verify_authenticode(filename):
    """Verify Authenticode signature and print certificate details."""
    binary = lief.PE.parse(filename)
    if binary is None:
        print(f"Error: failed to parse '{filename}' as PE")
        return False

    print(f"Authenticode Report: {filename}")
    print("=" * 48)

    if not binary.signatures:
        print("  Signature Present:          No")
        print()
        return True

    # Overall verification
    result = binary.verify_signature()
    is_valid = result == lief.PE.Signature.VERIFICATION_FLAGS.OK
    print(f"  {'Signature Present:':<30} Yes")
    print(f"  {'Verification:':<30} {'OK' if is_valid else str(result)}")

    # Authentihash digests
    print(f"  {'Authentihash (MD5):':<30} {binary.authentihash_md5.hex(':')}")
    print(f"  {'Authentihash (SHA-256):':<30} {binary.authentihash_sha256.hex(':')}")
    print()

    # Certificate chain for each signature
    for sig_idx, sig in enumerate(binary.signatures):
        label = f"Signature #{sig_idx}" if len(binary.signatures) > 1 else "Certificate Chain"
        print(f"  {label}:")
        print(f"    Digest Algorithm: {sig.digest_algorithm}")
        print()

        for idx, cert in enumerate(sig.certificates):
            print(f"    [{idx}] Subject: {cert.subject}")
            print(f"        Issuer:  {cert.issuer}")
            print(f"        Serial:  {cert.serial_number.hex(':')}")
            print(f"        Valid:   {cert.valid_from} -> {cert.valid_to}")
            print()

    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_binary> [pe_binary ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        verify_authenticode(path)
