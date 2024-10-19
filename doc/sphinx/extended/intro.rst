.. _extended-intro:

:fa:`cubes` What is LIEF Extended?
----------------------------------

*LIEF extended* is an enhanced version of LIEF that contains additional features
like the support of Objective-C metadata, PDB and DWARF.

Whilst the main version of LIEF is focused on (only) providing the support for
ELF, PE, and Mach-O, LIEF extended aims at providing other functionalities that
were not originally designed to be integrated in LIEF.

You can find the differences between both versions in this table:

+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| Module                        | Regular Version   | Extended Version  | Note                                                 |
+===============================+===================+===================+======================================================+
| :ref:`ELF <format-elf>`       | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`PE <format-pe>`         | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`Mach-O <format-macho>`  | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`DEX <format-dex>`       | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`OAT <format-oat>`       | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`VDEX <format-vdex>`     | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`ART <format-art>`       | :fa-check:`check` | :fa-check:`check` |                                                      |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`PDB <extended-pdb>`     | :xmark:`mark`     | :fa-check:`check` | Support based on LLVM                                |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`DWARF <extended-dwarf>` | :xmark:`mark`     | :fa-check:`check` | Support based on LLVM                                |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+
| :ref:`ObjC <extended-objc>`   | :xmark:`mark`     | :fa-check:`check` | Support based on :github-ref:`romainthomas/iCDump`   |
+-------------------------------+-------------------+-------------------+------------------------------------------------------+

To access the extended version, you must oauth-login with GitHub here: |lief-extended-url|.

.. image:: ../_static/login.webp
   :alt: LIEF Extended Login Interface
   :align: center

|

.. warning::

  LIEF extended is currently in a closed-beta state, please first reach out at
  |lief-extended-email| to get the access.

Once logged in, you can download the package of your choice
(e.g. LIEF Extended - Python 3.10 for macOS arm64)

.. note::

  There is a delay between each download.
