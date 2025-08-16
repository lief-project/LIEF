.. _plugins-ghidra:

:fa:`solid fa-dragon` Ghidra
----------------------------

.. raw:: html

  <hr />
  <img src="../../_static/lief_with_ghidra.webp" alt="Ghidra with LIEF" width=300px />

Similarly to the :ref:`BinaryNinja plugin <plugins-binaryninja>`, LIEF can be used
as a Ghidra plugin.

.. toctree::
  :caption: <i class="fa-solid fa-puzzle-piece">&nbsp;</i>Features
  :maxdepth: 1

  dwarf/index
  analyzers/loadconfig-analyzer/index
  analyzers/exceptions-analyzer/index

.. plugin-package:: ghidra
   :file: latest/plugins/index.json

:fa:`solid fa-gear` Installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, download the LIEF plugin package from here |lief-plugin-url| or
from the packages listed above. Then, follow the official procedure to install
extensions: `GhidraDocs/GettingStarted.md <https://github.com/NationalSecurityAgency/ghidra/blob/175cf9488722df3f8a718236c9e2c0ebfcd8cdb7/GhidraDocs/GettingStarted.md#extensions>`_

.. admonition:: Shared Library
  :class: warning

  In addition to the previously installed package, the plugins require to
  install ``LIEF.dll, libLIEF.dylib, or libLIEF.so`` next to the extension
  directory. You can download this library from the following list:

  .. sdk-package:: SDK
     :file: latest/sdk/index.json
     :filter: win64, linux-x86_64, darwin

  or from here: |lief-sdk-url|. Some plugins (like: :ref:`DWARF Plugin <plugins-ghidra-dwarf>`)
  need the extended version that can be downloaded from |lief-extended-url|.

  Given this shared library, you must copy it in the Ghidra settings directory.
  For instance:

  - OSX: ``~/Library/ghidra/ghidra_11.3.2_PUBLIC/Extensions/libLIEF.dylib``
  - Linux: ``~/.config/ghidra/ghidra_11.3.2_PUBLIC/Extensions/libLIEF.so``
  - Windows: ``C:\Users\romain\AppData\Roaming\ghidra\ghidra_11.3.2_PUBLIC\Extensions\LIEF.dll``
  - Windows: ``%APPDATA%\ghidra\ghidra_11.3.2_PUBLIC\Extensions\LIEF.dll``

You can verify that the plugin is correctly installed by opening the
``CodeBrowser`` tool on a binary and making sure that you can see LIEF
configuration in ``File > Configure`` (**from the CodeBrowser, not the projects window**)

Alternatively, you can try running the headless script: ``LiefVersionInfoScript.java``
which should output information about the installed version.

:fa:`solid fa-bug` Troubleshooting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Couldn't find the native library**

This means that ``libLIEF.so, libLIEF.dylib, or LIEF.dll`` is not correctly
installed in the ``Extensions/``. The details of the error provide the expected
path(s).

.. raw:: html

  <img style="max-width: 700px;" src="../../_static/cant-find-lib.png" alt="Ghidra native library issue" />
  <br />
  <br />

**This feature requires LIEF extended**

This error means that you need to install the extended version of the shared
library. See the :ref:`extended section <extended-intro>` for more information.

**libLIEF.dylib can't be opened because Apple cannot check it for malicious software**

``libLIEF.dylib`` is self-signed and does not use an Apple certificate so it's
considered as coming from an *unknown developer*.

You can address this issue in different ways:

1. You can compile ``libLIEF.dylib`` by yourself and sign the compiled library
   with your certificate.
2. You can add a security exception as described here: https://support.apple.com/guide/mac-help/apple-cant-check-app-for-malicious-software-mchleab3a043/mac

.. raw:: html

  <img style="max-width: 700px;" src="../../_static/macos-dylib-issue.png" alt="macOS library loading issue" />
  <br />
  <br />
