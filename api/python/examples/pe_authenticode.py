#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief

# Description:
# -----------
# Print certificates included in a signed PE
#
# Example:
# python pe_authenticode.py driver.sys
#
# Version:                      3
# Serial Number:                61:04:ca:69:00:00:00:00:00:08
# Signature Algorithm:          SHA1_WITH_RSA_ENCRYPTION
# Valid from:                   2007-6-5 22:3:21
# Valid to:                     2012-6-5 22:13:21
# Issuer:                       C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Time-Stamp PCA
# Subject:                      C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, OU=nCipher DSE ESN:A5B0-CDE0-DC94, CN=Microsoft Time-Stamp Service
#
# Version:                      3
# Serial Number:                61:01:c6:c1:00:00:00:00:00:07
# Signature Algorithm:          SHA1_WITH_RSA_ENCRYPTION
# Valid from:                   2008-10-22 20:39:22
# Valid to:                     2010-1-22 20:49:22
# Issuer:                       C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Verification PCA
# Subject:                      C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, OU=MOPR, CN=Microsoft Windows
# ....

def print_crt(binary):
    for crt in binary.signatures[0].certificates:
        print(crt)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <pe_binary>".format(sys.argv[0]))
        sys.exit(1)

    binary = lief.parse(sys.argv[1])
    print_crt(binary)



