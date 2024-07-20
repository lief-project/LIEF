#!/usr/bin/env python
import pytest
import json
import sys
from itertools import chain

import lief
from utils import get_sample, has_private_samples

try:
    sys.set_int_max_str_digits(0)
except:
    pass

def from_hex(x):
    return bytes.fromhex(x.replace(":", ""))

def int_from_bytes(x):
    return int.from_bytes(x, byteorder="little")

def test_api():
    avast = lief.PE.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"))

    assert avast.authentihash(lief.PE.ALGORITHMS.MD5) == from_hex("1c:a0:91:53:dc:9a:3a:5f:34:1d:7f:9b:b9:56:69:4d")
    assert avast.authentihash(lief.PE.ALGORITHMS.MD5) == avast.authentihash_md5

    assert avast.authentihash(lief.PE.ALGORITHMS.SHA_1) == from_hex("1e:ad:dc:29:1e:db:41:a2:69:c2:ba:ae:4b:fb:9d:31:e7:bb:ab:59")
    assert avast.authentihash(lief.PE.ALGORITHMS.SHA_1) == avast.authentihash_sha1

    assert avast.authentihash(lief.PE.ALGORITHMS.SHA_256) == from_hex("a7:38:da:44:46:a4:e7:8a:b6:47:db:7e:53:42:7e:b0:79:61:c9:94:31:7f:4c:59:d7:ed:be:a5:cc:78:6d:80")
    assert avast.authentihash(lief.PE.ALGORITHMS.SHA_256) == avast.authentihash_sha256

    assert avast.authentihash(lief.PE.ALGORITHMS.SHA_512) == from_hex("2a:e7:4c:81:0d:65:7b:6a:49:48:94:ab:b9:7d:fa:03:18:5d:48:cf:cd:4e:c2:99:f6:49:5f:db:30:64:78:03:f6:60:90:ab:04:84:01:36:7e:b0:6e:f6:29:b1:d1:a8:49:51:c3:4e:b3:75:89:c9:74:62:a2:2e:d2:ac:6e:96")
    assert avast.authentihash(lief.PE.ALGORITHMS.SHA_512) == avast.authentihash_sha512

    assert len(avast.signatures) == 1
    sig = avast.signatures[0]

    assert sig.version == 1
    assert sig.digest_algorithm == lief.PE.ALGORITHMS.SHA_256

    # Verify ContentInfo
    content_info = sig.content_info
    spc_indirect_data = content_info.value

    assert content_info.content_type == "1.3.6.1.4.1.311.2.1.4"
    assert content_info.digest == bytes(spc_indirect_data.digest)
    assert content_info.digest_algorithm == spc_indirect_data.digest_algorithm
    assert spc_indirect_data.digest_algorithm == lief.PE.ALGORITHMS.SHA_256
    assert spc_indirect_data.digest == from_hex("a7:38:da:44:46:a4:e7:8a:b6:47:db:7e:53:42:7e:b0:79:61:c9:94:31:7f:4c:59:d7:ed:be:a5:cc:78:6d:80")

    # Verify embedded certificates
    certs = sig.certificates
    assert len(certs) == 2
    cert_ca, cert_signer = certs

    assert cert_ca.version == 3
    assert cert_ca.serial_number == from_hex("04:09:18:1b:5f:d5:bb:66:75:53:43:b5:6f:95:50:08")
    assert cert_ca.signature_algorithm == "1.2.840.113549.1.1.11"
    assert cert_ca.valid_from == [2013, 10, 22, 12, 0, 0]
    assert cert_ca.valid_to == [2028, 10, 22, 12, 0, 0]
    assert cert_ca.issuer == "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA"
    assert cert_ca.subject == "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA"

    assert cert_signer.version == 3
    assert cert_signer.serial_number == from_hex("09:70:EF:4B:AD:5C:C4:4A:1C:2B:C3:D9:64:01:67:4C")
    assert cert_signer.signature_algorithm == "1.2.840.113549.1.1.11"
    assert cert_signer.valid_from == [2020, 4, 2, 0, 0, 0]
    assert cert_signer.valid_to == [2023, 3, 9, 12, 0, 0]
    assert cert_signer.issuer == "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA"
    assert cert_signer.subject == "C=CZ, L=Praha, O=Avast Software s.r.o., OU=RE stapler cistodc, CN=Avast Software s.r.o."

    assert cert_ca.verify(cert_signer) == lief.PE.x509.VERIFICATION_FLAGS.BADCERT_EXPIRED
    assert cert_ca.verify(cert_ca) == lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED
    assert cert_signer.is_trusted_by([cert_ca]) == lief.PE.x509.VERIFICATION_FLAGS.BADCERT_EXPIRED

    ca_bundles = lief.PE.x509.parse(get_sample("pkcs7/windows-ca-bundle.pem"))
    assert cert_ca.is_trusted_by(ca_bundles) == lief.PE.x509.VERIFICATION_FLAGS.OK

    # Verify signer(s)
    assert len(sig.signers) == 1
    signer = sig.signers[0]

    assert signer.version == 1
    assert signer.serial_number == from_hex("09:70:ef:4b:ad:5c:c4:4a:1c:2b:c3:d9:64:01:67:4c")
    assert signer.issuer == "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA"
    assert signer.digest_algorithm == lief.PE.ALGORITHMS.SHA_256
    assert signer.encryption_algorithm == lief.PE.ALGORITHMS.RSA
    assert signer.encrypted_digest.hex()[:16] == "758db1f480eb25ba"
    assert hash(signer.cert) == hash(cert_signer)

    # Check authenticated attributes
    auth_attrs = signer.authenticated_attributes
    assert len(auth_attrs) == 4

    content_type = auth_attrs[0]
    assert content_type.oid == "1.3.6.1.4.1.311.2.1.4"

    ms_spc_statement_type = auth_attrs[1]
    assert ms_spc_statement_type.oid == "1.3.6.1.4.1.311.2.1.21"

    spc_spopus_info = auth_attrs[2]
    assert spc_spopus_info.program_name == ""
    assert spc_spopus_info.more_info == "http://www.avast.com"

    pkcs9_message_digest = auth_attrs[3]
    assert pkcs9_message_digest.digest == from_hex("39:83:81:6a:7d:1c:62:96:25:40:ec:66:fa:87:90:fa:45:d1:06:3c:b2:3e:93:36:77:de:45:9f:0b:73:c5:77")

    # Check un-authenticated attributes
    unauth_attrs = signer.unauthenticated_attributes
    assert len(unauth_attrs) == 1

    ms_counter_sig = unauth_attrs[0]
    assert isinstance(ms_counter_sig, lief.PE.MsCounterSign)

    assert avast.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK
    # Verify the signature through a fake-detached signature
    pkcs7_sig = lief.PE.Signature.parse(list(sig.raw_der))
    assert avast.verify_signature(pkcs7_sig) == lief.PE.Signature.VERIFICATION_FLAGS.OK

def test_json_serialization():
    avast = lief.PE.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"))
    with open(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-signature.json"), "rb") as f:
        json_sig = json.load(f)
    print(lief.to_json(avast.signatures[0]))
    assert json.loads(lief.to_json(avast.signatures[0])) == json_sig

def test_fail():
    # Check bad-signed PE files
    avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-dos-stub.exe"))
    assert avast_altered.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK
    assert avast_altered.signatures[0].check() == lief.PE.Signature.VERIFICATION_FLAGS.OK

    avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-encrypted-digest.exe"))
    assert avast_altered.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK
    assert avast_altered.signatures[0].check() != lief.PE.Signature.VERIFICATION_FLAGS.OK

    avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-content-info-digest.exe"))
    assert avast_altered.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK
    assert avast_altered.signatures[0].check() != lief.PE.Signature.VERIFICATION_FLAGS.OK

    avast_altered = lief.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online-altered-pkcs9-msg-digest.exe"))
    assert avast_altered.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK
    assert avast_altered.signatures[0].check() != lief.PE.Signature.VERIFICATION_FLAGS.OK

def test_pkcs9_signing_time():
    sig = lief.PE.Signature.parse(get_sample("pkcs7/cert0.p7b"))
    attr = sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.PKCS9_SIGNING_TIME)
    assert attr.time == [2018, 8, 2, 15, 0, 12]

def test_pkcs9_at_sequence_number():
    sig = lief.PE.Signature.parse(get_sample("pkcs7/cert3.p7b"))
    nested_sig = sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.MS_SPC_NESTED_SIGN).signature
    at_seq_nb = nested_sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.PKCS9_AT_SEQUENCE_NUMBER)
    assert at_seq_nb.number == 1

def test_spc_sp_opus_info():
    sig = lief.PE.Signature.parse(get_sample("pkcs7/cert11.p7b"))
    spc = sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.SPC_SP_OPUS_INFO)

    assert spc.program_name == "Slideshow Generator Powertoy for WinXP"
    assert spc.more_info == "http://www.microsoft.com/windowsxp"

    sig = lief.PE.Signature.parse(get_sample("pkcs7/cert9.p7b"))
    spc = sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.SPC_SP_OPUS_INFO)
    assert spc.program_name == "Microsoft Windows"
    assert spc.more_info == "http://www.microsoft.com/windows"

def test_pkcs9_counter_signature():
    sig = lief.PE.Signature.parse(get_sample("pkcs7/cert10.p7b"))
    counter_sign = sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.PKCS9_COUNTER_SIGNATURE)

    signer = counter_sign.signer

    assert signer.version == 1
    assert signer.serial_number == from_hex("0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50")
    assert signer.issuer == "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA - G2"
    assert signer.digest_algorithm == lief.PE.ALGORITHMS.SHA_1
    assert signer.encryption_algorithm == lief.PE.ALGORITHMS.RSA
    assert signer.encrypted_digest.hex()[:30] == "92db1faf4b20293109bcddbb6ed7a3"
    assert len(signer.authenticated_attributes) == 3
    assert len(signer.unauthenticated_attributes) == 0

    content_type, sig_time, msg_digest = signer.authenticated_attributes
    assert content_type.oid == "1.2.840.113549.1.7.1"
    assert sig_time.time == [2018, 7, 25, 18, 14, 50]
    assert msg_digest.digest == from_hex("05:ca:7d:34:f0:ef:c2:70:33:4c:f9:90:77:a5:bc:86:6e:46:be:45")

def test_ms_spc_nested_signature():
    sig = lief.PE.Signature.parse(get_sample("pkcs7/cert0.p7b"))
    attr = sig.signers[0].get_attribute(lief.PE.Attribute.TYPE.MS_SPC_NESTED_SIGN)
    nested_sig = attr.signature

    assert nested_sig.version == 1
    assert nested_sig.digest_algorithm == lief.PE.ALGORITHMS.SHA_256

    content_info = nested_sig.content_info
    spc_indirect_data = content_info.value
    print(spc_indirect_data)


    assert spc_indirect_data.content_type == "1.3.6.1.4.1.311.2.1.4"
    assert spc_indirect_data.digest_algorithm == lief.PE.ALGORITHMS.SHA_256
    assert spc_indirect_data.digest == from_hex("90:a4:df:36:26:df:d9:8d:6b:3b:1d:42:74:5b:94:54:c5:e2:30:2e:d2:f8:23:70:16:3f:1e:e6:dd:7d:8c:91")

    certs = nested_sig.certificates
    assert len(certs) == 3
    nvidia_cert, self_signed_ca, signer_cert = certs

    assert nvidia_cert.issuer == "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 SHA256 Code Signing CA - G2"
    assert nvidia_cert.subject == "C=US, ST=California, L=Santa Clara, O=NVIDIA Corporation, OU=IT-MIS, CN=NVIDIA Corporation"
    assert nvidia_cert.serial_number == from_hex("62:E7:45:E9:21:65:21:3C:97:1F:5C:49:0A:EA:12:A5")

    assert self_signed_ca.issuer == r"C=US, O=VeriSign\, Inc., OU=VeriSign Trust Network, OU=(c) 2008 VeriSign\, Inc. - For authorized use only, CN=VeriSign Universal Root Certification Authority"
    assert self_signed_ca.subject == r"C=US, O=VeriSign\, Inc., OU=VeriSign Trust Network, OU=(c) 2008 VeriSign\, Inc. - For authorized use only, CN=VeriSign Universal Root Certification Authority"
    assert self_signed_ca.serial_number == from_hex("40:1A:C4:64:21:B3:13:21:03:0E:BB:E4:12:1A:C5:1D")

    assert signer_cert.issuer == r"C=US, O=VeriSign\, Inc., OU=VeriSign Trust Network, OU=(c) 2008 VeriSign\, Inc. - For authorized use only, CN=VeriSign Universal Root Certification Authority"
    assert signer_cert.subject == "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 SHA256 Code Signing CA - G2"
    assert signer_cert.serial_number == from_hex("7C:1B:35:35:4A:E7:DB:74:E7:41:5F:11:69:CA:6B:A8")

    # Check self-signed
    assert self_signed_ca.verify(self_signed_ca) == lief.PE.x509.VERIFICATION_FLAGS.OK

    assert signer_cert.is_trusted_by([self_signed_ca]) == lief.PE.x509.VERIFICATION_FLAGS.OK
    assert self_signed_ca.verify(signer_cert) == lief.PE.x509.VERIFICATION_FLAGS.OK
    assert signer_cert.verify(nvidia_cert) == lief.PE.x509.VERIFICATION_FLAGS.BADCERT_EXPIRED

    ca_bundles = lief.PE.x509.parse(get_sample("pkcs7/windows-ca-bundle.pem"))
    assert self_signed_ca.is_trusted_by(ca_bundles) == lief.PE.x509.VERIFICATION_FLAGS.OK
    assert int(nvidia_cert.is_trusted_by(ca_bundles)) == \
           lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED | lief.PE.x509.VERIFICATION_FLAGS.BADCERT_EXPIRED

    assert nested_sig.check() == lief.PE.Signature.VERIFICATION_FLAGS.OK

    signer = nested_sig.signers[0]
    print(signer)

def test_self_signed():
    selfsigned = lief.parse(get_sample("PE/PE32_x86-64_binary_self-signed.exe"))
    sig = selfsigned.signatures[0]
    ca_bundles = lief.PE.x509.parse(get_sample("pkcs7/windows-ca-bundle.pem"))
    cert_ca, cert_signer = sig.certificates
    assert cert_ca.verify(cert_signer) == lief.PE.x509.VERIFICATION_FLAGS.OK
    assert cert_ca.is_trusted_by(ca_bundles) == lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED

def test_rsa_info():
    avast = lief.PE.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"))
    cert_ca, cert_signer = avast.signatures[0].certificates
    assert cert_ca.key_type == lief.PE.x509.KEY_TYPES.RSA
    rsa_info = cert_ca.rsa_info
    assert rsa_info.key_size == 2048
    assert rsa_info.has_public_key
    assert not rsa_info.has_private_key

    N = int_from_bytes(rsa_info.N)
    E = int_from_bytes(rsa_info.E)
    D = int_from_bytes(rsa_info.D)
    P = int_from_bytes(rsa_info.P)
    Q = int_from_bytes(rsa_info.Q)

    assert E == 65537
    assert str(N)[:70] == "2645636708930440977121533117630461323983500317859148049010916849328467"
    assert D == 0
    assert P == 0
    assert Q == 0

def test_issue_703():
    sig: lief.PE.Signature = lief.PE.Signature.parse(get_sample("pkcs7/cert_issue_703.der"))
    assert sig.certificates[0].issuer == "CN=TxExoTiQueMoDz\\\\Tx ExoTiQueMoDz"
    assert sig.certificates[0].subject == "CN=TxExoTiQueMoDz\\\\Tx ExoTiQueMoDz"

def test_issue_912():
    steam = lief.PE.parse(get_sample("PE/steam.exe"))
    assert steam.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK

def test_verification_flags_str():
    flag = lief.PE.Signature.VERIFICATION_FLAGS.BAD_DIGEST | \
           lief.PE.Signature.VERIFICATION_FLAGS.CERT_FUTURE
    assert str(flag) == "lief.PE.VERIFICATION_FLAGS.BAD_DIGEST | lief.PE.VERIFICATION_FLAGS.CERT_FUTURE"
    assert repr(flag) == "<lief.PE.VERIFICATION_FLAGS.BAD_DIGEST | CERT_FUTURE: 2176>"
    assert str(lief.PE.Signature.VERIFICATION_FLAGS.from_value(0)) == "lief.PE.VERIFICATION_FLAGS.OK"

def test_ms_manifest_binary_id():
    acres = lief.PE.parse(get_sample("PE/AcRes.dll"))
    attr = acres.signatures[0].signers[0].get_auth_attribute(lief.PE.Attribute.TYPE.MS_PLATFORM_MANIFEST_BINARY_ID)
    assert attr is not None
    assert attr.manifest_id == "Q3XarTZK62/v5aPftDNzWYB5ybbMDvHGQIYjVa+ja+0="

def test_ms_counter_signature():
    #lief.logging.set_level(lief.logging.LEVEL.DEBUG)
    acres = lief.PE.parse(get_sample("PE/AppVClient.exe"))
    sig = acres.signatures[0]
    ms_counter_sig: lief.PE.MsCounterSign = sig.signers[0].get_unauth_attribute(lief.PE.Attribute.TYPE.MS_COUNTER_SIGN)
    assert ms_counter_sig is not None
    assert ms_counter_sig.version == 3
    assert ms_counter_sig.digest_algorithm == lief.PE.ALGORITHMS.SHA_256

    content_info = ms_counter_sig.content_info
    assert content_info.digest_algorithm == lief.PE.ALGORITHMS.UNKNOWN
    assert content_info.content_type == "1.2.840.113549.1.9.16.1.4"

    content_info_value = content_info.value
    assert isinstance(content_info_value, lief.PE.PKCS9TSTInfo)

    certs = list(ms_counter_sig.certificates)

    assert len(certs) == 2
    assert certs[0].issuer == "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Time-Stamp PCA 2010"
    assert certs[1].issuer == "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Root Certificate Authority 2010"

    signers = list(ms_counter_sig.signers)
    assert len(signers) == 1

    signer = signers[0]
    assert signer.version == 1
    assert signer.digest_algorithm == lief.PE.ALGORITHMS.SHA_256
    assert signer.encryption_algorithm == lief.PE.ALGORITHMS.SHA_256_RSA
    assert signer.issuer == "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Time-Stamp PCA 2010"
    assert ":".join(map(lambda e: f"{e:02x}", signer.serial_number)) == "33:00:00:01:b7:21:27:1a:07:a2:2a:86:46:00:01:00:00:01:b7"

    auth_attrs = signer.authenticated_attributes
    assert len(auth_attrs) == 3
    assert auth_attrs[0].type == lief.PE.Attribute.TYPE.CONTENT_TYPE
    assert auth_attrs[1].type == lief.PE.Attribute.TYPE.PKCS9_MESSAGE_DIGEST
    assert auth_attrs[2].type == lief.PE.Attribute.TYPE.SIGNING_CERTIFICATE_V2
    assert isinstance(auth_attrs[2], lief.PE.SigningCertificateV2)

    unauth_attrs = signer.unauthenticated_attributes
    assert len(unauth_attrs) == 0

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_playready_signature():
    pe = lief.PE.parse(get_sample("private/PE/Windows.Media.Protection.PlayReady.dll"))

    sig = pe.signatures[0]
    spc = sig.signers[0].get_auth_attribute(lief.PE.Attribute.TYPE.SPC_RELAXED_PE_MARKER_CHECK)
    assert spc is not None
