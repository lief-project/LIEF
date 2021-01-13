#!/usr/bin/env python
import lief
import sys
import os

# Parse PE file
pe = lief.parse(sys.argv[1])

sep = (":") if sys.version_info.minor > 7 else ()

# Get authenticode
print(pe.authentihash_md5.hex(*sep)) # 1c:a0:91:53:dc:9a:3a:5f:34:1d:7f:9b:b9:56:69:4d
print(pe.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(*sep)) # 1e:ad:dc:29:1e:db:41:a2:69:c2:ba:ae:4b:fb:9d:31:e7:bb:ab:59

# Check signature according to PKCS #7 and Microsoft documentation
print(pe.verify_signature()) # Return VERIFICATION_FLAGS.OK

bin_ca = None
# Look for the root CA in the PE file
for crt in pe.signatures[0].certificates:
    if crt.issuer == "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA":
        bin_ca = crt

# Verify CA chain
bundle_path = os.getenv("LIEF_CA_BUNDLE", None) # Path to CA bundle (one can use those from signify:
                                                # signify/certs/authenticode-bundle.pem)
if bundle_path is not None:
    # Parse cert bundle and return a list of lief.PE.x509 objects
    bundle = lief.PE.x509.parse(bundle_path)
    print(bin_ca.is_trusted_by(bundle)) # VERIFICATION_FLAGS.OK


# Get the certificate used by the signer
cert_signer = pe.signatures[0].signers[0].cert
print(cert_signer)
bin_ca.verify(cert_signer) # Verify that cert_signer is signed the the CA

# running with:
# LIEF_CA_BUNDLE=signify/signify/certs/authenticode-bundle.pem python ./authenticode.py avast_free_antivirus_setup_online.exe
#
# 1c:a0:91:53:dc:9a:3a:5f:34:1d:7f:9b:b9:56:69:4d
# 1e:ad:dc:29:1e:db:41:a2:69:c2:ba:ae:4b:fb:9d:31:e7:bb:ab:59
# VERIFICATION_FLAGS.OK
# cert. version     : 3
# serial number     : 04:09:18:1B:5F:D5:BB:66:75:53:43:B5:6F:95:50:08
# issuer name       : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA
# subject name      : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
# issued  on        : 2013-10-22 12:00:00
# expires on        : 2028-10-22 12:00:00
# signed using      : RSA with SHA-256
# RSA key size      : 2048 bits
# basic constraints : CA=true, max_pathlen=0
# key usage         : Digital Signature, Key Cert Sign, CRL Sign
# ext key usage     : Code Signing
#
# VERIFICATION_FLAGS.OK
