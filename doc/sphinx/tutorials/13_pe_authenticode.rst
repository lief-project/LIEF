.. _pe-authenticode:

13 - PE Authenticode
--------------------

This tutorial explains how to process and verify PE Authenticode with LIEF.

------

Introduction
~~~~~~~~~~~~

PE Authenticode is the signature scheme used by Windows to sign and verify the
integrity of PE executables. The signature is associated with the
:attr:`~lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE` data directory, which is
not always tied to a section (implying that the signature is not necessarily
mapped into memory). In fact, the data directory entry points to a file offset,
not an RVA. This signature is wrapped in a PKCS #7 container with custom object
types, as defined in the official documentation [#]_.

Parsing these signatures has been a goal since LIEF's inception. Before
version :ref:`v0.11.0 <release-0110>`, the implementation was incomplete and
sometimes inaccurate. Since version :ref:`v0.11.0 <release-0110>`, and thanks
to sponsorship from the `CERT Gouvernemental of Luxembourg <https://www.govcert.lu/en/>`_,
we have refactored the Authenticode parser [#]_ and implemented signature
verification functions.


Exploring the PKCS #7 Signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The LIEF API exposes most internal components of the PKCS #7 container
associated with Authenticode. First, we can access the PE signatures through
the |lief-pe-binary-signatures| attribute [#]_:

.. code-block:: python

   import lief
   pe = lief.parse("avast_free_antivirus_setup_online.exe")
   print(len(pe.signatures))

   signature = pe.signatures[0]

Although we usually find only **one** signature, PE executables can embed
multiple signatures using the ``/as`` command of ``signtool.exe``. This is why
the :attr:`~lief.PE.Binary.signatures` attribute returns an **iterator** over
the signatures parsed by LIEF.

The :class:`signature <lief.PE.Signature>` variable is a
|lief-pe-signature| object, which mirrors the PKCS #7 container and
includes methods for verifying its integrity.

Within this object, we can access the following attributes:

* :class:`~lief.PE.x509` certificates used to sign the executable: :attr:`lief.PE.Signature.certificates`
* The :class:`~lief.PE.ContentInfo` object containing the authentihash: :attr:`lief.PE.ContentInfo.digest`
* The :class:`~lief.PE.SignerInfo` structures: :attr:`lief.PE.Signature.signers`

  .. note::

    While the PKCS #7 standard supports multiple signers, Microsoft
    specifications require **exactly one** signer.

The ``__str__()`` methods of these objects are overloaded to facilitate
pretty-printing their content:

.. code-block:: python

   # Print certificate information
   for crt in signature.certificates:
     print(crt)

   # Print the authentihash value embedded in the signature
   print(signature.content_info.digest.hex())

   # Print signer information
   print(signature.signers[0])

.. code-block:: text

  cert. version     : 3
  serial number     : 04:09:18:1B:5F:D5:BB:66:75:53:43:B5:6F:95:50:08
  issuer name       : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA
  subject name      : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
  issued  on        : 2013-10-22 12:00:00
  expires on        : 2028-10-22 12:00:00
  signed using      : RSA with SHA-256
  RSA key size      : 2048 bits
  basic constraints : CA=true, max_pathlen=0
  key usage         : Digital Signature, Key Cert Sign, CRL Sign
  ext key usage     : Code Signing

  cert. version     : 3
  serial number     : 09:70:EF:4B:AD:5C:C4:4A:1C:2B:C3:D9:64:01:67:4C
  issuer name       : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
  subject name      : C=CZ, L=Praha, O=Avast Software s.r.o., OU=RE stapler cistodc, CN=Avast Software s.r.o.
  issued  on        : 2020-04-02 00:00:00
  expires on        : 2023-03-09 12:00:00
  signed using      : RSA with SHA-256
  RSA key size      : 2048 bits
  basic constraints : CA=false
  key usage         : Digital Signature
  ext key usage     : Code Signing

  a738da4446a4e78ab647db7e53427eb07961c994317f4c59d7edbea5cc786d80
  SHA_256/RSA - C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA - 4 auth attr - 1 unauth attr

For PE files, the authentihash is computed using the
:meth:`lief.PE.Binary.authentihash` function, which takes a
:class:`lief.PE.ALGORITHMS` enum as a parameter to define the hash algorithm.

For instance, to compute the SHA-256 authentihash, pass
:attr:`lief.PE.ALGORITHMS.SHA_256`:

.. code-block:: python

   print(pe.authentihash(lief.PE.ALGORITHMS.SHA_256).hex())

.. code-block:: text

  a738da4446a4e78ab647db7e53427eb07961c994317f4c59d7edbea5cc786d80

.. note::

  To compare the :meth:`lief.PE.Binary.authentihash` value with the signed one
  (i.e., :attr:`lief.PE.ContentInfo.digest`), you must use the same hash
  algorithm as defined by :attr:`lief.PE.Signature.digest_algorithm`.

We also provide shortcut attributes in the Python API to compute authentihash
values:

+----------------+---------------------------------------------+
| Hash Algorithm | Binary Attribute                            |
+================+=============================================+
| MD5            | :attr:`~lief.PE.Binary.authentihash_md5`    |
+----------------+---------------------------------------------+
| SHA1           | :attr:`~lief.PE.Binary.authentihash_sha1`   |
+----------------+---------------------------------------------+
| SHA-256        | :attr:`~lief.PE.Binary.authentihash_sha256` |
+----------------+---------------------------------------------+
| SHA-512        | :attr:`~lief.PE.Binary.authentihash_sha512` |
+----------------+---------------------------------------------+

LIEF also exposes the original raw signature blob via the
:attr:`lief.PE.Signature.raw_der` property, which allows for exporting the
signature:

.. code-block:: python

  from pathlib import Path

  Path("/tmp/extracted.p7b").write_bytes(signature.raw_der)

Then, you can use ``openssl`` to process its content:

.. code-block:: text

   $ openssl pkcs7 -inform der -print -in /tmp/extracted.p7b -noout -text
   ...
        sig_alg:
          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
          parameter: NULL
        signature:  (0 unused bits)
          0000 - 31 c3 a7 f3 70 e3 2c 49-15 bd f4 09 6c 27 4e   1...p.,I....l'N
          000f - 00 a9 23 df cb ea 7f 99-55 cb 24 88 75 e8 c4   ..#.....U.$.u..
          001e - de 48 4f 70 dd 2a 27 5c-df be 36 f6 84 0d ad   .HOp.*'\..6....
          002d - 35 5e 65 f7 af 55 01 7a-2d 01 18 a0 d6 98 a4   5^e..U.z-......
          003c - d1 bd 19 e9 a4 03 f4 a3-4d 12 6e 72 5f 6b 3a   ........M.nr_k:
          004b - b8 de 45 f1 63 80 b0 47-42 f6 38 b8 e7 5b dd   ..E.c..GB.8..[.
          005a - cf f2 f8 c2 61 4b 2c 19-b7 7d 78 8f 2e 0c b0   ....aK,..}x....
          0069 - 7c f2 d9 8e 9f 65 4e 21-63 19 6a 5b 0c 91 12   |....eN!c.j[...
          0078 - 44 29 fe 91 d5 6f 5d 9c-4d 7b a1 74 c6 69 d9   D)...o].M{.t.i.
          0087 - e7 23 26 54 35 5c 38 33-c5 a7 92 0d 70 a5 2a   .#&T5\83....p.*
          0096 - 33 77 4a fc 86 b0 fa 59-2f 24 f6 a1 45 b2 09   3wJ....Y/$..E..
          00a5 - 75 2d a1 81 68 e4 67 11-46 e3 fb bf 0c c5 d5   u-..h.g.F......
          00b4 - d7 7b 7b 35 fb d6 e8 4a-c9 13 82 82 a7 0c 3e   .{{5...J......>
          00c3 - 6f 61 e0 37 15 e0 37 5d-b8 22 14 ad 54 58 0e   oa.7..7]."..TX.
          00d2 - 95 6c 2b b1 d2 c7 6c 86-a1 9f fa d8 37 ca f7   .l+...l.....7..
          00e1 - 56 75 b0 9d df 7c 46 43-20 87 8a a3 81 47 82   Vu...|FC ....G.
          00f0 - 99 57 87 12 46 96 02 7c-a7 77 b9 42 4d c8 05   .W..F..|.w.BM..
          00ff - 0a                                             .
    crl:
      <ABSENT>
    signer_info:
        version: 1
        issuer_and_serial:
          issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
          serial: 12549442701880659695003200114191853388
        digest_alg:
          algorithm: sha256 (2.16.840.1.101.3.4.2.1)
          parameter: NULL
        auth_attr:
            object: contentType (1.2.840.113549.1.9.3)
            set:
              OBJECT:undefined (1.3.6.1.4.1.311.2.1.4)

            object: undefined (1.3.6.1.4.1.311.2.1.11)

The `authenticode_reader.py <https://github.com/lief-project/LIEF/blob/main/api/python/examples/authenticode/authenticode_reader.py>`_
script in the `examples/ <https://github.com/lief-project/LIEF/tree/main/examples/python/authenticode>`_ directory
can also be used to inspect the signature:

.. code-block:: console

   $ python authenticode_reader.py --all avast_free_antivirus_setup_online.exe

.. code-block:: text

   Signature version : 1
   Digest Algorithm  : ALGORITHMS.SHA_256
   Content Info:
     Content Type    : 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_CONTENT)
     Digest Algorithm: ALGORITHMS.SHA_256
     Digest          : a738da4446a4e78ab647db7e53427eb07961c994317f4c59d7edbea5cc786d80
   Certificates
     Version            : 3
     Issuer             : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA
     Subject            : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
     Serial Number      : 0409181b5fd5bb66755343b56f955008
     Signature Algorithm: SHA256_WITH_RSA_ENCRYPTION
     Valid from         : 2013/10/22 - 12:00:00
     Valid to           : 2028/10/22 - 12:00:00
     Key usage          : CRL_SIGN - KEY_CERT_SIGN - DIGITAL_SIGNATURE
     Ext key usage      : CODE_SIGNING
     RSA key size       : 2048
     ===========================================
     Version            : 3
     Issuer             : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
     Subject            : C=CZ, L=Praha, O=Avast Software s.r.o., OU=RE stapler cistodc, CN=Avast Software s.r.o.
     Serial Number      : 0970ef4bad5cc44a1c2bc3d96401674c
     Signature Algorithm: SHA256_WITH_RSA_ENCRYPTION
     Valid from         : 2020/04/02 - 00:00:00
     Valid to           : 2023/03/09 - 12:00:00
     Key usage          : DIGITAL_SIGNATURE
     Ext key usage      : CODE_SIGNING
     RSA key size       : 2048
     ===========================================
   Signer(s)
     Version             : 1
     Serial Number       : 0970ef4bad5cc44a1c2bc3d96401674c
     Issuer              : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA
     Digest Algorithm    : ALGORITHMS.SHA_256
     Encryption Algorithm: ALGORITHMS.RSA
     Encrypted Digest    : 758db1f480eb25bada6c ...
     Authenticated attributes:
        Content Type OID: 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_CONTENT)
        MS Statement type OID: 1.3.6.1.4.1.311.2.1.21 (INDIVIDUAL_CODE_SIGNING)
        Info: http://www.avast.com
        PKCS9 Message Digest: 3983816a7d1c62962540ec66fa8790fa45d1063cb23e933677de459f0b73c577
     Un-authenticated attributes:
        Generic Type 1.3.6.1.4.1.311.3.3.1 (MS_COUNTER_SIGN)

Verifying the Signature
~~~~~~~~~~~~~~~~~~~~~~~

In addition to parsing Authenticode signatures, LIEF can also verify the
integrity of the authentihash using the
|lief-pe-binary-verify_signature| method. This method returns
:attr:`lief.PE.Signature.VERIFICATION_FLAGS.OK` if the signature is valid, or
another enum value if it is invalid (see:
:attr:`lief.PE.Signature.VERIFICATION_FLAGS`):

.. code-block:: python

   pe = lief.parse("avast_free_antivirus_setup_online.exe")
   print(pe.verify_signature()) # lief.PE.Signature.VERIFICATION_FLAGS.OK

You can also verify a PE binary with a **detached signature** by providing a
:class:`signature <lief.PE.Signature>` object to
:meth:`~lief.PE.Binary.verify_signature`:

.. code-block:: python
   :emphasize-lines: 3,4

   pe = lief.parse("avast_free_antivirus_setup_online.exe")

   detached_sig = lief.PE.Signature.parse("/tmp/detached.p7b")
   print(pe.verify_signature(detached_sig))

The verification process does not rely on external components (i.e., neither
OpenSSL nor the WinTrust API). Instead, we attempt to reproduce the same checks
described in the RFCs and official Authenticode documentation [#]_.

These checks include:

A. Verifying the integrity of the signature (:meth:`lief.PE.Signature.check()`):

   1. Ensuring there is exactly one :class:`~lief.PE.SignerInfo` structure.
   2. Confirming that digest algorithms are consistent
      (:attr:`Signature.digest_algorithm <lief.PE.Signature.digest_algorithm>` ``==`` :attr:`ContentInfo.digest_algorithm <lief.PE.ContentInfo.digest_algorithm>`  ``==`` :attr:`SignerInfo.digest_algorithm <lief.PE.SignerInfo.digest_algorithm>`).
   3. If :class:`~lief.PE.SignerInfo` has authenticated attributes, verifying
      their integrity. Otherwise, verifying the integrity of the
      :class:`~lief.PE.ContentInfo` against the signer's certificate.
   4. If authenticated attributes exist, confirming the presence of a
      :class:`lief.PE.PKCS9MessageDigest` attribute whose
      :attr:`~lief.PE.PKCS9MessageDigest.digest` matches the hash of the
      :class:`~lief.PE.ContentInfo`.
   5. If a countersignature exists in the **unauthenticated attributes**,
      verifying its integrity and ensuring it includes a valid *timestamp*.
   6. Checking certificate expiration relative to any *timestamp*.

B. If the signature is valid, confirming that :attr:`lief.PE.ContentInfo.digest`
   matches the computed :meth:`~lief.PE.Binary.authentihash`.

These checks represent the default behavior of
:meth:`~lief.PE.Binary.verify_signature`. You can, however, pass
:class:`lief.PE.Signature.VERIFICATION_CHECKS` flags to customize this
behavior:

:Hash Only:

    Using :attr:`VERIFICATION_CHECKS.HASH_ONLY <lief.PE.Signature.VERIFICATION_CHECKS.HASH_ONLY>`
    only performs step ``B)`` (i.e., checks the authentihash values regardless
    of signature integrity).

    .. code-block:: python

      pe.verify_signature(lief.PE.Signature.VERIFICATION_CHECKS.HASH_ONLY)


:Lifetime Signing:

    Using :attr:`VERIFICATION_CHECKS.LIFETIME_SIGNING <lief.PE.Signature.VERIFICATION_CHECKS.LIFETIME_SIGNING>`
    allows timestamped signatures to expire if their certificate has expired.
    This corresponds to `WTD_LIFETIME_SIGNING_FLAG <https://docs.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data#WTD_LIFETIME_SIGNING_FLAG>`_.

    .. code-block:: python

      pe.verify_signature(lief.PE.Signature.VERIFICATION_CHECKS.LIFETIME_SIGNING)
      signature.check(lief.PE.Signature.VERIFICATION_CHECKS.LIFETIME_SIGNING)


:Skip Certificate Time Check:

    Using :attr:`VERIFICATION_CHECKS.SKIP_CERT_TIME <lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME>`
    prevents LIEF from raising an error if certificates have expired.

    .. code-block:: python

      # Returns lief.PE.Signature.VERIFICATION_FLAGS.OK even if
      # the certificates have expired
      pe.verify_signature(lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME)
      signature.check(lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME)

.. note::

  To verify the integrity of a :class:`~lief.PE.Signature` object, you can use
  |lief-pe-signature-check|.


Certificate Chain of Trust
~~~~~~~~~~~~~~~~~~~~~~~~~~

Finally, the certificate chain can be verified using:

1. :meth:`lief.PE.x509.verify`
2. :meth:`lief.PE.x509.is_trusted_by`

:meth:`~lief.PE.x509.verify` is used to verify a signed certificate against its
CA. Given a CA :class:`~lief.PE.x509` certificate, ``CA.verify(signed)``
confirms that the ``signed`` parameter was indeed signed by ``CA``.

Alternatively, :meth:`~lief.PE.x509.is_trusted_by` checks whether a given
:class:`~lief.PE.x509` certificate can be verified against a **list of
certificates**:

.. code-block:: python

  CA_BUNDLE = lief.PE.x509.parse("ms_bundle.pem")
  signer = signature.signers[0]
  print(signer.cert.is_trusted_by(CA_BUNDLE))

.. code-block:: python

  cert1 = lief.PE.x509.parse("ca1.crt")
  cert2 = lief.PE.x509.parse("ca2.crt")

  print(signer.cert.is_trusted_by([cert1, cert2]))


Limitations
~~~~~~~~~~~

Regarding the PKCS #7 structure, LIEF can parse and process most of its
elements. However, the :class:`lief.PE.SignerInfo` structure can embed
attributes (authenticated or otherwise) whose ASN.1 structure may or may not
be public. As of LIEF v0.11.0, the following OIDs are not yet supported:

+----------------------------+--------------------------------------------------------------+
| OID                        | Description                                                  |
+============================+==============================================================+
| 1.3.6.1.4.1.311.3.3.1      | Ms-CounterSign (undocumented, supported in LIEF 0.15.0)      |
+----------------------------+--------------------------------------------------------------+
| 1.2.840.113549.1.9.16.2.12 | S/MIME Signing certificate (id-aa-signingCertificate)        |
+----------------------------+--------------------------------------------------------------+
| 1.3.6.1.4.1.311.2.6.1      | SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID                          |
+----------------------------+--------------------------------------------------------------+
| 1.3.6.1.4.1.311.10.3.28    | szOID_PLATFORM_MANIFEST_BINARY_ID (supported in LIEF 0.15.0) |
+----------------------------+--------------------------------------------------------------+

These unsupported attributes are wrapped in the :class:`lief.PE.GenericType`,
which exposes the raw ASN.1 blob via the :attr:`~lief.PE.GenericType.raw_content`
property.

Conclusion
~~~~~~~~~~

Under the hood, most of the work is performed by
`mbedtls <https://github.com/Mbed-TLS/mbedtls>`_, which provides the following
primitives used by LIEF:

- ASN.1 decoder
- x509 certificate processing (parsing AND verification)
- Hash algorithms
- Public key algorithms

A small C++ snippet can also be cross-compiled for iOS:

.. code-block:: cpp

   #include <LIEF/PE.hpp>

   int main(int argc, char** argv) {
     std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(argv[1])
     if (pe->verify_signature() == LIEF::PE::Signature::VERIFICATION_FLAGS.OK) {
       std::cout << "Signature ok!" << "\n";
       return 0;
     }
     std::cout << "Error!" << "\n";
     return 1;
   }

This allows for verifying the integrity of a PE executable on an iPhone:

.. code-block:: console

  iPhone:~ root# file PE32_x86-64_binary_avast-free-antivirus-setup-online.exe
  PE32_x86-64_binary_avast-free-antivirus-setup-online.exe: PE32 executable (GUI) Intel 80386, for MS Windows
  iPhone:~ root# file ./pe_authenticode_check
  ./pe_authenticode_check: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|WEAK_DEFINES|BINDS_TO_WEAK|PIE|HAS_TLV_DESCRIPTORS>
  iPhone:~ root# ./pe_authenticode_check PE32_x86-64_binary_avast-free-antivirus-setup-online.exe
  Signature ok!
  iPhone:~ root#

While this example may seem niche, it highlights the project's purpose:

- Providing a cross-platform and cross-format library.
- Exposing both a high-level API (Python) and a low-level API (C++).
- Minimizing dependencies so that the static version of LIEF does not require external libraries [#]_.

..  code-block:: console

   $ otool -L pe_authenticode_check

   /System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 1770.255.0)
   /usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
   /usr/lib/libc++.1.dylib (compatibility version 1.0.0, current version 904.4.0)
   /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1292.60.1)


In addition to LIEF, you may be interested in other projects that handle
Authenticode:

+------------------+------------------------------------------------------------------------------+
| Project          | URL                                                                          |
+==================+==============================================================================+
| signify          | https://github.com/ralphje/signify                                           |
+------------------+------------------------------------------------------------------------------+
| winsign          | https://github.com/mozilla-releng/winsign                                    |
+------------------+------------------------------------------------------------------------------+
| uthenticode      | https://github.com/trailofbits/uthenticode                                   |
+------------------+------------------------------------------------------------------------------+
| AuthenticodeLint | https://github.com/vcsjones/AuthenticodeLint                                 |
+------------------+------------------------------------------------------------------------------+
| osslsigncode     | https://github.com/mtrojnar/osslsigncode                                     |
+------------------+------------------------------------------------------------------------------+
| yara-x           | https://github.com/VirusTotal/yara-x (which has support for PE Authenticode) |
+------------------+------------------------------------------------------------------------------+

Finally, additional information about Authenticode can be found in the Trail of
Bits blog post [#]_. For Authenticode techniques used by Dropbox, refer to the
Microsoft website [#]_. If you are interested in how PKCS #7 integrity works,
refer to *Manually verify PKCS#7 signed data with OpenSSL* [#]_.


.. rubric:: References

.. [#] http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx

.. [#] Which is now exception-free.

.. [#] This tutorial uses the Python API, but the C++ API is very similar.

.. [#] See `src/PE/signature/Signature.cpp - check() <https://github.com/lief-project/LIEF/tree/master/src/PE/signature/Signature.cpp>`_ for the implementation.

.. [#] Except for the C/C++ STL.

.. [#] https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows/

.. [#] https://docs.microsoft.com/en-us/archive/blogs/ieinternals/caveats-for-authenticode-code-signing

.. [#] http://qistoph.blogspot.com/2012/01/manual-verify-pkcs7-signed-data-with.html



.. rubric:: API

* |lief-pe-binary-verify_signature|
* :meth:`lief.PE.Binary.authentihash`
* :attr:`lief.PE.Binary.authentihash_md5`
* :attr:`lief.PE.Binary.authentihash_sha1`
* :attr:`lief.PE.Binary.authentihash_sha256`
* :attr:`lief.PE.Binary.authentihash_sha512`
* |lief-pe-binary-signatures|

* |lief-pe-signature|
* :class:`lief.PE.x509`
* :class:`lief.PE.ContentInfo`
* :class:`lief.PE.SignerInfo`
* :class:`lief.PE.Attribute`
* :class:`lief.PE.ContentType`
* :class:`lief.PE.GenericType`
* :class:`lief.PE.MsSpcNestedSignature`
* :class:`lief.PE.MsSpcStatementType`
* :class:`lief.PE.PKCS9AtSequenceNumber`
* :class:`lief.PE.PKCS9CounterSignature`
* :class:`lief.PE.PKCS9MessageDigest`
* :class:`lief.PE.PKCS9SigningTime`
* :class:`lief.PE.SpcSpOpusInfo`


.. include:: ../_cross_api.rst
