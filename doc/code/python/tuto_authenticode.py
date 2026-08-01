import lief


def signatures(pe: lief.PE.Binary) -> lief.PE.Signature:
    # lief-doc: signatures-start
    pe: lief.PE.Binary

    print(len(pe.signatures))

    signature = pe.signatures[0]
    # lief-doc: signatures-end
    return signature


def signature_info(signature: lief.PE.Signature) -> None:
    # lief-doc: signature-info-start
    signature: lief.PE.Signature

    # Print certificate information
    for crt in signature.certificates:
        print(crt)

    # Print the authentihash value embedded in the signature
    print(signature.content_info.digest.hex())

    # Print signer information
    print(signature.signers[0])
    # lief-doc: signature-info-end


def compute_authentihash(pe: lief.PE.Binary) -> None:
    # lief-doc: authentihash-start
    pe: lief.PE.Binary

    print(pe.authentihash(lief.PE.ALGORITHMS.SHA_256).hex())
    # lief-doc: authentihash-end


def extract_raw_der(signature: lief.PE.Signature) -> None:
    # lief-doc: raw-der-start
    from pathlib import Path

    signature: lief.PE.Signature

    Path("/tmp/extracted.p7b").write_bytes(signature.raw_der)
    # lief-doc: raw-der-end


def verify(pe: lief.PE.Binary) -> None:
    # lief-doc: verify-start
    pe: lief.PE.Binary

    print(pe.verify_signature())  # lief.PE.Signature.VERIFICATION_FLAGS.OK
    # lief-doc: verify-end


def verify_detached(pe: lief.PE.Binary) -> None:
    # lief-doc: verify-detached-start
    pe: lief.PE.Binary

    detached_sig = lief.PE.Signature.parse("/tmp/detached.p7b")
    assert isinstance(detached_sig, lief.PE.Signature)

    print(pe.verify_signature(detached_sig))
    # lief-doc: verify-detached-end


def verify_hash_only(pe: lief.PE.Binary) -> None:
    # lief-doc: verify-hash-only-start
    pe: lief.PE.Binary

    pe.verify_signature(lief.PE.Signature.VERIFICATION_CHECKS.HASH_ONLY)
    # lief-doc: verify-hash-only-end


def verify_lifetime(pe: lief.PE.Binary, signature: lief.PE.Signature) -> None:
    # lief-doc: verify-lifetime-start
    pe: lief.PE.Binary
    signature: lief.PE.Signature

    pe.verify_signature(lief.PE.Signature.VERIFICATION_CHECKS.LIFETIME_SIGNING)
    signature.check(lief.PE.Signature.VERIFICATION_CHECKS.LIFETIME_SIGNING)
    # lief-doc: verify-lifetime-end


def verify_skip_cert_time(pe: lief.PE.Binary, signature: lief.PE.Signature) -> None:
    # lief-doc: verify-skip-cert-time-start
    pe: lief.PE.Binary
    signature: lief.PE.Signature

    # Returns lief.PE.Signature.VERIFICATION_FLAGS.OK even if
    # the certificates have expired
    pe.verify_signature(lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME)
    signature.check(lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME)
    # lief-doc: verify-skip-cert-time-end


def is_trusted_by_bundle(signature: lief.PE.Signature) -> None:
    # lief-doc: is-trusted-bundle-start
    signature: lief.PE.Signature

    CA_BUNDLE = lief.PE.x509.parse("ms_bundle.pem")
    signer = signature.signers[0]
    print(signer.cert.is_trusted_by(CA_BUNDLE))
    # lief-doc: is-trusted-bundle-end


def is_trusted_by_list(signer: lief.PE.SignerInfo) -> None:
    # lief-doc: is-trusted-list-start
    signer: lief.PE.SignerInfo

    cert1 = lief.PE.x509.parse("ca1.crt")[0]
    cert2 = lief.PE.x509.parse("ca2.crt")[0]

    print(signer.cert.is_trusted_by([cert1, cert2]))
    # lief-doc: is-trusted-list-end
