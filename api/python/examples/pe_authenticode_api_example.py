#!/usr/bin/env python
"""Walk-through of LIEF's Authenticode API.

Exercises the most useful entry points of the Authenticode surface:
computing authentihashes, calling ``verify_signature``, iterating
over the certificate chain and verifying the chain against a trust
bundle pointed to by the ``LIEF_CA_BUNDLE`` environment variable.

Example:

    $ LIEF_CA_BUNDLE=/path/to/authenticode-bundle.pem \\
        python api_example.py avast_free_antivirus_setup_online.exe
"""

import argparse
import os
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", help="Path to a PE binary")
    parser.add_argument(
        "--bundle",
        default=os.getenv("LIEF_CA_BUNDLE"),
        help="Path to a PEM bundle of trust anchors "
             "(default: $LIEF_CA_BUNDLE)",
    )
    args = parser.parse_args()

    pe = lief.PE.parse(args.binary)
    if pe is None:
        print(f"Error: failed to parse '{args.binary}' as PE", file=sys.stderr)
        return 1

    # Authentihash digests.
    print(pe.authentihash_md5.hex(":"))
    print(pe.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(":"))

    # PKCS #7 signature verification.
    print(pe.verify_signature())

    if not pe.signatures:
        print("No signature embedded in the PE", file=sys.stderr)
        return 1

    signature = pe.signatures[0]

    # Look for a well-known DigiCert root CA in the embedded chain.
    bin_ca = None
    target_issuer = (
        "C=US, O=DigiCert Inc, OU=www.digicert.com, "
        "CN=DigiCert Assured ID Root CA"
    )
    for crt in signature.certificates:
        if crt.issuer == target_issuer:
            bin_ca = crt
            break
    if bin_ca is None:
        print("No DigiCert root CA found in the signature chain", file=sys.stderr)
        return 1

    # Verify the selected CA against an external trust bundle (e.g. the
    # authenticode bundle shipped with signify).
    if args.bundle is not None:
        bundle = lief.PE.x509.parse(args.bundle)
        print(bin_ca.is_trusted_by(bundle))

    # Verify that the signer certificate was signed by the selected CA.
    cert_signer = signature.signers[0].cert
    print(cert_signer)
    if cert_signer is None:
        print("Signer certificate is missing", file=sys.stderr)
        return 1
    print(bin_ca.verify(cert_signer))
    return 0


if __name__ == "__main__":
    sys.exit(main())
