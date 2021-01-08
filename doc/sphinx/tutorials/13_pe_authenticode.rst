13 - PE Authenticode
--------------------

This tutorial introduces the new API deal with PE Authenticode processing.

By Romain Thomas - `@rh0main <https://twitter.com/rh0main>`_

------

Introduction
~~~~~~~~~~~~

.. TODO



.. rubric:: References


.. TODO

   https://github.com/ralphje/signify
   https://signify.readthedocs.io/en/latest/authenticode.html

  https://github.com/trailofbits/uthenticode
  https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows/


.. rubric:: API

* :meth:`lief.PE.Binary.verify_signature`
* :meth:`lief.PE.Binary.authentihash`
* :attr:`lief.PE.Binary.authentihash_md5`
* :attr:`lief.PE.Binary.authentihash_sha1`
* :attr:`lief.PE.Binary.authentihash_sha256`
* :attr:`lief.PE.Binary.authentihash_sha512`
* :attr:`lief.PE.Binary.signatures`

* :class:`lief.PE.Signature`
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

