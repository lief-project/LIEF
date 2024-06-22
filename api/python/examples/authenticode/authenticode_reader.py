#!/usr/bin/env python
import lief
from lief.PE import oid_to_string
import argparse
import json
import sys
import string
import argparse
import traceback
import pathlib

try:
    from prettyprinter import pprint
except ImportError:
    from pprint import pprint

HAS_EXCEPTION = False
class exceptions_handler(object):
    func = None

    def __init__(self, exceptions, on_except_callback=None):
        self.exceptions         = exceptions
        self.on_except_callback = on_except_callback

    def __call__(self, *args, **kwargs):
        if self.func is None:
            self.func = args[0]
            return self
        try:
            return self.func(*args, **kwargs)
        except self.exceptions as e:
            HAS_EXCEPTION = True
            if self.on_except_callback is not None:
                self.on_except_callback(e)
            else:
                print("-" * 60, file=sys.stderr)
                print("Exception in {}: {}".format(self.func.__name__, e))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)
                print("-" * 60, file=sys.stderr)

@exceptions_handler(Exception)
def print_attr(indent: int, auth: lief.PE.Attribute):
    if auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.CONTENT_TYPE:
        print_content_type(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_SIGNING_TIME:
        print_signing_time(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.MS_SPC_STATEMENT_TYPE:
        print_ms_statement_type(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_MESSAGE_DIGEST:
        print_pkcs_msg_dg(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_COUNTER_SIGNATURE:
        print_pkcs_counter_sig(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.GENERIC_TYPE:
        print_generic_type(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.SPC_SP_OPUS_INFO:
        print_spc_sp_opus_info(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.MS_SPC_NESTED_SIGN:
        print_ms_nested_sig(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_AT_SEQUENCE_NUMBER:
        print_pkcs9_at_seq_number(indent, auth)
    else:
        print(" " * indent, type(auth), auth)


@exceptions_handler(Exception)
def print_pkcs9_at_seq_number(indent: int, auth: lief.PE.PKCS9AtSequenceNumber):
    print("{} PKCS #9 sequence number: {}".format(" " * indent, auth.number))

@exceptions_handler(Exception)
def print_ms_nested_sig(indent: int, auth: lief.PE.MsSpcNestedSignature):
    print("{} MS Nested Signature:".format(" " * indent))
    print_all(auth.signature, indent + 2)

@exceptions_handler(Exception)
def print_spc_sp_opus_info(indent: int, auth: lief.PE.SpcSpOpusInfo):
    if len(auth.program_name) > 0 and len(auth.more_info) > 0:
        print("{} Info: {} {}".format(" " * indent, auth.program_name, auth.more_info))
    elif len(auth.program_name) > 0 and len(auth.more_info) == 0:
        print("{} Info: {}".format(" " * indent, auth.program_name))
    elif len(auth.program_name) == 0 and len(auth.more_info) > 0:
        print("{} Info: {}".format(" " * indent, auth.more_info))
    else:
        print("{} Info: <empty>".format(" " * indent))

@exceptions_handler(Exception)
def print_generic_type(indent: int, auth: lief.PE.GenericType):
    print("{} Generic Type {} ({})".format(" " * indent, auth.oid, lief.PE.oid_to_string(auth.oid)))

@exceptions_handler(Exception)
def print_content_type(indent: int, auth: lief.PE.ContentType):
    print("{} Content Type OID: {} ({})".format(" " * indent, auth.oid, lief.PE.oid_to_string(auth.oid)))

@exceptions_handler(Exception)
def print_signing_time(indent: int, auth: lief.PE.PKCS9SigningTime):
    print("{} Signing Time: {}/{:02}/{:02} - {:02}:{:02}:{:02}".format(" " * indent, *auth.time))

@exceptions_handler(Exception)
def print_ms_statement_type(indent: int, auth: lief.PE.MsSpcStatementType):
    print("{} MS Statement type OID: {} ({})".format(" " * indent, auth.oid, lief.PE.oid_to_string(auth.oid)))

@exceptions_handler(Exception)
def print_pkcs_msg_dg(indent: int, auth: lief.PE.PKCS9MessageDigest):
    print("{} PKCS9 Message Digest: {}".format(" " * indent, auth.digest.hex()))

@exceptions_handler(Exception)
def print_crt(indent: int, crt: lief.PE.x509):
    print("{}  Version            : {:d}".format(" " * indent, crt.version))
    print("{}  Issuer             : {}".format(" " * indent, crt.issuer))
    print("{}  Subject            : {}".format(" " * indent, crt.subject))
    print("{}  Serial Number      : {}".format(" " * indent, crt.serial_number.hex()))
    print("{}  Signature Algorithm: {}".format(" " * indent, lief.PE.oid_to_string(crt.signature_algorithm)))
    print("{}  Valid from         : {}/{:02d}/{:02d} - {:02d}:{:02d}:{:02d}".format(" " * indent, *crt.valid_from))
    print("{}  Valid to           : {}/{:02d}/{:02d} - {:02d}:{:02d}:{:02d}".format(" " * indent, *crt.valid_to))
    if len(crt.key_usage) > 0:
        print("{}  Key usage          : {}".format(" " * indent, " - ".join(str(e).split(".")[-1] for e in crt.key_usage)))
    if len(crt.ext_key_usage) > 0:
        print("{}  Ext key usage      : {}".format(" " * indent, " - ".join(lief.PE.oid_to_string(e) for e in crt.ext_key_usage)))
    if crt.rsa_info is not None:
        rsa_info = crt.rsa_info
        print("{}  RSA key size       : {}".format(" " * indent, rsa_info.key_size))
    print("{}  ===========================================".format(" " * indent))

@exceptions_handler(Exception)
def print_pkcs_counter_sig(indent: int, auth: lief.PE.PKCS9CounterSignature):
    print("{} PKCS9 counter signature".format(" " * indent))
    signer = auth.signer
    print("{}   Version             : {:d}".format(" " * indent, signer.version))
    print("{}   Serial Number       : {}".format(" " * indent, signer.serial_number.hex()))
    print("{}   Issuer              : {}".format(" " * indent, signer.issuer))
    print("{}   Digest Algorithm    : {}".format(" " * indent, signer.digest_algorithm))
    print("{}   Encryption Algorithm: {}".format(" " * indent, signer.encryption_algorithm))
    print("{}   Encrypted Digest    : {} ...".format(" " * indent, signer.encrypted_digest.hex()[:20]))

    if len(signer.authenticated_attributes) > 0:
        print("{}   Authenticated attributes:".format(" " * indent))
        for auth in signer.authenticated_attributes:
            print_attr(indent + 4, auth)

    if len(signer.unauthenticated_attributes) > 0:
        print("{}   Un-Authenticated attributes:".format(" " * indent))
        for auth in signer.unauthenticated_attributes:
            print_attr(indent + 4, auth)
@exceptions_handler(Exception)
def print_all(sig: lief.PE.Signature, indent: int = 2):
    ci: lief.PE.ContentInfo = sig.content_info
    print("{}Signature version : {}".format(" " * indent, sig.version))
    print("{}Digest Algorithm  : {!s}".format(" " * indent, sig.digest_algorithm))
    print("{}Content Info:".format(" " * indent))
    print("{}  Content Type    : {!s} ({})".format(" " * indent, ci.content_type, lief.PE.oid_to_string(ci.content_type)))
    print("{}  Digest Algorithm: {!s}".format(" " * indent, ci.digest_algorithm))
    print("{}  Digest          : {!s}".format(" " * indent, ci.digest.hex()))
    print("{}Certificates".format(" " * indent))
    for crt in sig.certificates:
        print_crt(indent, crt)
    print("{}Signer(s)".format(" " * indent))
    for signer in sig.signers:
        print("{}  Version             : {:d}".format(" " * indent, signer.version))
        print("{}  Serial Number       : {}".format(" " * indent, signer.serial_number.hex()))
        print("{}  Issuer              : {}".format(" " * indent, signer.issuer))
        print("{}  Digest Algorithm    : {}".format(" " * indent, signer.digest_algorithm))
        print("{}  Encryption Algorithm: {}".format(" " * indent, signer.encryption_algorithm))
        print("{}  Encrypted Digest    : {} ...".format(" " * indent, signer.encrypted_digest.hex()[:20]))
        if len(signer.authenticated_attributes) > 0:
            print("{}  Authenticated attributes:".format(" " * indent))
            for auth in signer.authenticated_attributes:
                print_attr(indent + 4, auth)

        if len(signer.unauthenticated_attributes) > 0:
            print("{}  Un-authenticated attributes:".format(" " * indent))
            for auth in signer.unauthenticated_attributes:
                print_attr(indent + 4, auth)


@exceptions_handler(Exception)
def show_crts(sig: lief.PE.Signature, args):
    for crt in sig.certificates:
        print_crt(0, crt)

@exceptions_handler(Exception)
def process_signature(sig: lief.PE.Signature, args):
    if args.show_all:
        print_all(sig)

    if args.show_crt:
        show_crts(sig, args)

    if args.show_hash:
        print("Authentihash: {}".format(sig.content_info.digest.hex()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")

    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all information')

    parser.add_argument('-c', '--crt',
            action='store_true', dest='show_crt',
            help='Show embedded x509 certificates')

    parser.add_argument('-H', '--hash',
            action='store_true', dest='show_hash',
            help='Show the autentihash value')

    parser.add_argument('-C', '--check',
            action='store_true', dest='check_sig',
            help='Check the signature')

    parser.add_argument('-D', '--allow-expired',
            action='store_true', dest='allow_expired',
            help='Allow expired certificates')

    parser.add_argument('-s', '--save',
            dest='ext_file_path',
            help='Extract and save the PKCS #7')


    # Logging setup
    logger_group = parser.add_argument_group('Logger')
    verbosity = logger_group.add_mutually_exclusive_group()

    verbosity.add_argument('--debug',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.DEBUG)

    verbosity.add_argument('--trace',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.TRACE)

    verbosity.add_argument('--info',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.INFO)

    verbosity.add_argument('--warn',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.WARN)

    verbosity.add_argument('--err',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.ERROR)

    verbosity.add_argument('--critical',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.CRITICAL)

    parser.set_defaults(main_verbosity=lief.logging.LEVEL.WARN)

    args = parser.parse_args()
    lief.logging.set_level(args.main_verbosity)

    if lief.is_pe(args.file):
        binary = None
        try:
            binary: lief.PE.Binary = lief.PE.parse(args.file)
            if binary is None:
                print("Error while parsing {}".format(args.file))
                sys.exit(1)
        except lief.exception as e:
            print(e)
            sys.exit(1)

        if args.check_sig:
            flags = lief.PE.Signature.VERIFICATION_CHECKS.DEFAULT
            if args.allow_expired:
                flags = lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME
            res = binary.verify_signature(flags)
            print(res)

        if args.show_hash:
            print("Binary MD5     authentihash: {}".format(binary.authentihash_md5.hex()))
            print("Binary SHA-1   authentihash: {}".format(binary.authentihash_sha1.hex()))
            print("Binary SHA-256 authentihash: {}".format(binary.authentihash_sha256.hex()))

        for idx, sig in enumerate(binary.signatures):
            process_signature(sig, args)
            if args.ext_file_path:
                path = args.ext_file_path
                if idx > 0:
                    path += str(idx)
                if not path.endswith(".p7b"):
                    path += ".p7b"
                outpath = pathlib.Path(path)
                outpath.write_bytes(sig.raw_der)
                print("Signature saved to {}".format(outpath))
    else:
        # Try as a regular p7b signature
        sig = lief.PE.Signature.parse(args.file)
        if sig is None:
            print("Fail to parse the signature")
            sys.exit(1)
        process_signature(sig, args)


if __name__ == "__main__":
    main()
    if HAS_EXCEPTION:
        sys.exit(1)
