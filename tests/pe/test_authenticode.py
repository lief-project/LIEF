#!/usr/bin/env python
import itertools
import logging
import os
import random
import stat
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import TestCase

import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

def from_hex(x):
    return bytes.fromhex(x.replace(":", ""))

class TestAuthenticode(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_api(self):
        avast = lief.PE.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"))

        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.MD5), from_hex("1c:a0:91:53:dc:9a:3a:5f:34:1d:7f:9b:b9:56:69:4d"))
        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.MD5), avast.authentihash_md5)

        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.SHA_1), from_hex("1e:ad:dc:29:1e:db:41:a2:69:c2:ba:ae:4b:fb:9d:31:e7:bb:ab:59"))
        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.SHA_1), avast.authentihash_sha1)

        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.SHA_256), from_hex("a7:38:da:44:46:a4:e7:8a:b6:47:db:7e:53:42:7e:b0:79:61:c9:94:31:7f:4c:59:d7:ed:be:a5:cc:78:6d:80"))
        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.SHA_256), avast.authentihash_sha256)

        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.SHA_512), from_hex("2a:e7:4c:81:0d:65:7b:6a:49:48:94:ab:b9:7d:fa:03:18:5d:48:cf:cd:4e:c2:99:f6:49:5f:db:30:64:78:03:f6:60:90:ab:04:84:01:36:7e:b0:6e:f6:29:b1:d1:a8:49:51:c3:4e:b3:75:89:c9:74:62:a2:2e:d2:ac:6e:96"))
        self.assertEqual(avast.authentihash(lief.PE.ALGORITHMS.SHA_512), avast.authentihash_sha512)

        self.assertEqual(len(avast.signatures), 1)
        sig = avast.signatures[0]

        self.assertEqual(sig.version, 1)
        self.assertEqual(sig.digest_algorithm, lief.PE.ALGORITHMS.SHA_256)

        # Verify ContentInfo
        content_info = sig.content_info

        self.assertEqual(content_info.content_type, "1.3.6.1.4.1.311.2.1.4")
        self.assertEqual(content_info.digest_algorithm, lief.PE.ALGORITHMS.SHA_256)
        self.assertEqual(content_info.digest, from_hex("a7:38:da:44:46:a4:e7:8a:b6:47:db:7e:53:42:7e:b0:79:61:c9:94:31:7f:4c:59:d7:ed:be:a5:cc:78:6d:80"))

        # Verify embedded certificates
        certs = sig.certificates
        self.assertEqual(len(certs), 2)
        cert_ca, cert_signer = certs

        self.assertEqual(cert_ca.version, 3)
        self.assertEqual(cert_ca.serial_number, from_hex("04:09:18:1b:5f:d5:bb:66:75:53:43:b5:6f:95:50:08"))
        self.assertEqual(cert_ca.signature_algorithm, "1.2.840.113549.1.1.11")
        self.assertEqual(cert_ca.valid_from, [2013, 10, 22, 12, 0, 0])
        self.assertEqual(cert_ca.valid_to,   [2028, 10, 22, 12, 0, 0])
        self.assertEqual(cert_ca.issuer, "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA")
        self.assertEqual(cert_ca.subject, "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA")

        self.assertEqual(cert_signer.version, 3)
        self.assertEqual(cert_signer.serial_number, from_hex("09:70:EF:4B:AD:5C:C4:4A:1C:2B:C3:D9:64:01:67:4C"))
        self.assertEqual(cert_signer.signature_algorithm, "1.2.840.113549.1.1.11")
        self.assertEqual(cert_signer.valid_from, [2020, 4, 2, 0, 0, 0])
        self.assertEqual(cert_signer.valid_to,   [2023, 3, 9, 12, 0, 0])
        self.assertEqual(cert_signer.issuer, "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA")
        self.assertEqual(cert_signer.subject, "C=CZ, L=Praha, O=Avast Software s.r.o., OU=RE stapler cistodc, CN=Avast Software s.r.o.")

        self.assertEqual(cert_ca.verify(cert_signer), lief.PE.x509.VERIFICATION_FLAGS.OK)
        self.assertEqual(cert_ca.verify(cert_ca), lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED)
        self.assertEqual(cert_signer.is_trusted_by([cert_ca]), lief.PE.x509.VERIFICATION_FLAGS.OK)

        ca_bundles = lief.PE.x509.parse(get_sample("pkcs7/windows-ca-bundle.pem"))
        self.assertEqual(cert_ca.is_trusted_by(ca_bundles), lief.PE.x509.VERIFICATION_FLAGS.OK)

        # Verify signer(s)
        self.assertEqual(len(sig.signers), 1)
        signer = sig.signers[0]

        self.assertEqual(signer.version, 1)
        self.assertEqual(signer.serial_number, from_hex("09:70:ef:4b:ad:5c:c4:4a:1c:2b:c3:d9:64:01:67:4c"))
        self.assertEqual(signer.issuer, "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA")
        self.assertEqual(signer.digest_algorithm, lief.PE.ALGORITHMS.SHA_256)
        self.assertEqual(signer.encryption_algorithm, lief.PE.ALGORITHMS.RSA)
        self.assertEqual(signer.encrypted_digest.hex(":")[:23], "75:8d:b1:f4:80:eb:25:ba")
        self.assertEqual(hash(signer.cert), hash(cert_signer))

        # Check authenticated attributes
        auth_attrs = signer.authenticated_attributes
        self.assertEqual(len(auth_attrs), 4)

        content_type = auth_attrs[0]
        self.assertEqual(content_type.oid, "1.3.6.1.4.1.311.2.1.4")

        ms_spc_statement_type = auth_attrs[1]
        self.assertEqual(ms_spc_statement_type.oid, "1.3.6.1.4.1.311.2.1.21")

        spc_spopus_info = auth_attrs[2]
        self.assertEqual(spc_spopus_info.program_name, "")
        self.assertEqual(spc_spopus_info.more_info, "http://www.avast.com")

        pkcs9_message_digest = auth_attrs[3]
        self.assertEqual(pkcs9_message_digest.digest, from_hex("39:83:81:6a:7d:1c:62:96:25:40:ec:66:fa:87:90:fa:45:d1:06:3c:b2:3e:93:36:77:de:45:9f:0b:73:c5:77"))

        # Check un-authenticated attributes
        unauth_attrs = signer.unauthenticated_attributes
        self.assertEqual(len(unauth_attrs), 1)

        ms_counter_sig = unauth_attrs[0]
        # TODO(romain): Currently we do not support the (undocumented) Ms-CounterSignature attribute
        # Therefore it is wrapped through lief.PE.GenericType. The first assert should fail when
        # it will be implemented
        self.assertTrue(isinstance(ms_counter_sig, lief.PE.GenericType))
        self.assertEqual(ms_counter_sig.oid, "1.3.6.1.4.1.311.3.3.1")

        self.assertEqual(avast.verify_signature(), lief.PE.Signature.VERIFICATION_FLAGS.OK)
        # Verify the signature through a fake-detached signature
        pkcs7_sig = lief.PE.Signature.parse(list(sig.raw_der))
        self.assertEqual(avast.verify_signature(pkcs7_sig), lief.PE.Signature.VERIFICATION_FLAGS.OK)


    def test_json_serialization(self):
        avast = lief.PE.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"))
        with open(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-signature.json"), "rb") as f:
            json_sig = json.load(f)
        self.assertEqual(json.loads(lief.to_json(avast.signatures[0])), json_sig)


    def test_fail(self):
        # Check bad-signed PE files

        avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-dos-stub.exe"))
        self.assertNotEqual(avast_altered.verify_signature(), lief.PE.Signature.VERIFICATION_FLAGS.OK)
        self.assertEqual(avast_altered.signatures[0].check(), lief.PE.Signature.VERIFICATION_FLAGS.OK)

        avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-encrypted-digest.exe"))
        self.assertNotEqual(avast_altered.verify_signature(), lief.PE.Signature.VERIFICATION_FLAGS.OK)
        self.assertNotEqual(avast_altered.signatures[0].check(), lief.PE.Signature.VERIFICATION_FLAGS.OK)

        avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-content-info-digest.exe"))
        self.assertNotEqual(avast_altered.verify_signature(), lief.PE.Signature.VERIFICATION_FLAGS.OK)
        self.assertNotEqual(avast_altered.signatures[0].check(), lief.PE.Signature.VERIFICATION_FLAGS.OK)

        avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-pkcs9-msg-digest.exe"))
        self.assertNotEqual(avast_altered.verify_signature(), lief.PE.Signature.VERIFICATION_FLAGS.OK)
        self.assertNotEqual(avast_altered.signatures[0].check(), lief.PE.Signature.VERIFICATION_FLAGS.OK)


    def test_pkcs9_signing_time(self):
        sig = lief.PE.Signature.parse(get_sample("pkcs7/cert0.p7b"))
        attr = sig.signers[0].get_attribute(lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_SIGNING_TIME)
        self.assertEqual(attr.time, [2018, 8, 2, 15, 0, 12])

    def test_pkcs9_at_sequence_number(self):
        sig = lief.PE.Signature.parse(get_sample("pkcs7/cert10.p7b"))

    def test_spc_sp_opuse_info(self):
        sig = lief.PE.Signature.parse(get_sample("pkcs7/cert10.p7b"))
        sig = lief.PE.Signature.parse(get_sample("pkcs7/cert11.p7b"))

    def test_pkcs9_counter_signature(self):
        sig = lief.PE.Signature.parse(get_sample("pkcs7/cert10.p7b"))

    def test_ms_spc_nested_signature(self):
        sig = lief.PE.Signature.parse(get_sample("pkcs7/cert0.p7b"))
        attr = sig.signers[0].get_attribute(lief.PE.SIG_ATTRIBUTE_TYPES.MS_SPC_NESTED_SIGN)
        nested_sig = attr.signature
        print(nested_sig)

        self.assertEqual(nested_sig.version, 1)
        self.assertEqual(nested_sig.digest_algorithm, lief.PE.ALGORITHMS.SHA_256)

        content_info = nested_sig.content_info

        self.assertEqual(content_info.content_type, "1.3.6.1.4.1.311.2.1.4")
        self.assertEqual(content_info.digest_algorithm, lief.PE.ALGORITHMS.SHA_256)
        self.assertEqual(content_info.digest, from_hex("90:a4:df:36:26:df:d9:8d:6b:3b:1d:42:74:5b:94:54:c5:e2:30:2e:d2:f8:23:70:16:3f:1e:e6:dd:7d:8c:91"))

        certs = nested_sig.certificates
        self.assertEqual(len(certs), 3)
        nvidia_cert, self_signed_ca, signer_cert = certs

        self.assertEqual(nvidia_cert.issuer, "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 SHA256 Code Signing CA - G2")
        self.assertEqual(nvidia_cert.subject, "C=US, ST=California, L=Santa Clara, O=NVIDIA Corporation, OU=IT-MIS, CN=NVIDIA Corporation")
        self.assertEqual(nvidia_cert.serial_number, from_hex("62:E7:45:E9:21:65:21:3C:97:1F:5C:49:0A:EA:12:A5"))

        self.assertEqual(self_signed_ca.issuer, "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2008 VeriSign, Inc. - For authorized use only, CN=VeriSign Universal Root Certification Authority")
        self.assertEqual(self_signed_ca.subject, "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2008 VeriSign, Inc. - For authorized use only, CN=VeriSign Universal Root Certification Authority")
        self.assertEqual(self_signed_ca.serial_number, from_hex("40:1A:C4:64:21:B3:13:21:03:0E:BB:E4:12:1A:C5:1D"))

        self.assertEqual(signer_cert.issuer, "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2008 VeriSign, Inc. - For authorized use only, CN=VeriSign Universal Root Certification Authority")
        self.assertEqual(signer_cert.subject, "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 SHA256 Code Signing CA - G2")
        self.assertEqual(signer_cert.serial_number, from_hex("7C:1B:35:35:4A:E7:DB:74:E7:41:5F:11:69:CA:6B:A8"))

        # Check self-signed
        self.assertEqual(self_signed_ca.verify(self_signed_ca), lief.PE.x509.VERIFICATION_FLAGS.OK)

        self.assertEqual(signer_cert.is_trusted_by([self_signed_ca]), lief.PE.x509.VERIFICATION_FLAGS.OK)
        self.assertEqual(self_signed_ca.verify(signer_cert), lief.PE.x509.VERIFICATION_FLAGS.OK)
        self.assertEqual(signer_cert.verify(nvidia_cert), lief.PE.x509.VERIFICATION_FLAGS.OK)

        ca_bundles = lief.PE.x509.parse(get_sample("pkcs7/windows-ca-bundle.pem"))
        self.assertEqual(self_signed_ca.is_trusted_by(ca_bundles), lief.PE.x509.VERIFICATION_FLAGS.OK)
        self.assertEqual(nvidia_cert.is_trusted_by(ca_bundles), lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED)

        self.assertEqual(nested_sig.check(), lief.PE.Signature.VERIFICATION_FLAGS.OK)

        signer = nested_sig.signers[0]

    def test_self_signed(self):
        selfsigned = lief.parse(get_sample("PE/PE32_x86-64_binary_self-signed.exe"))
        sig = selfsigned.signatures[0]
        ca_bundles = lief.PE.x509.parse(get_sample("pkcs7/windows-ca-bundle.pem"))
        cert_ca, cert_signer = sig.certificates
        self.assertEqual(cert_ca.verify(cert_signer), lief.PE.x509.VERIFICATION_FLAGS.OK)
        self.assertEqual(cert_ca.is_trusted_by(ca_bundles), lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED)

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
