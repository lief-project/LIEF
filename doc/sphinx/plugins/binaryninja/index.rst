.. _plugins-binaryninja:

:fa:`solid fa-user-ninja` BinaryNinja
-------------------------------------

.. raw:: html

  <hr />
  <img src="../../_static/lief_with_bn.webp" width=300px />

Similarly to the :ref:`Ghidra plugin <plugins-ghidra>`, LIEF can be used
as a BinaryNinja plugin.

.. toctree::
  :caption: <i class="fa-solid fa-puzzle-piece">&nbsp;</i>Features
  :maxdepth: 2

  dwarf/index
  analyzers/elf/index
  analyzers/pe/index

.. plugin-package:: binaryninja
   :file: latest/plugins/index.json

First, download the LIEF plugin package from here |lief-plugin-url| or
from the packages listed above. Then, follow the official procedure to install
plugins: https://docs.binary.ninja/guide/plugins.html

For instance, if you install the :ref:`DWARF Plugin <plugins-binaryninja-dwarf>`,
you should have this file installed:

* **Linux:** ``~/.binaryninja/plugins/lief-dwarf-plugin-linux-x86_64.so``
* **Windows:** ``C:\Users\romain\AppData\Roaming\Binary Ninja\plugins\lief-dwarf-plugin-windows-x86_64.dll``
* **macOS:** ``~/Library/Application Support/Binary Ninja/plugins/lief-dwarf-plugin-darwin-arm64.dylib``

.. admonition:: Shared Library
  :class: warning

  In addition to the previously installed library, the plugins require to
  install ``LIEF.dll, libLIEF.dylib, or libLIEF.so`` next to the plugin
  directory. You can download this library from the following list:

  .. sdk-package:: SDK
     :file: latest/sdk/index.json
     :filter: win64, linux-x86_64, darwin

  or from here: |lief-sdk-url|. Some plugins (like: :ref:`DWARF Plugin <plugins-binaryninja-dwarf>`)
  need the extended version that can be downloaded from |lief-extended-url|.

  Given this shared library, you must copy it in the plugin directory (or its
  parent for Linux and macOS).

  - **macOS**:

    - ``~/Library/Application Support/Binary Ninja/plugins/libLIEF.dylib``
    - ``~/Library/Application Support/Binary Ninja/libLIEF.dylib``

  - **Linux**:

    - ``~/.binaryninja/plugins/libLIEF.so``
    - ``~/.binaryninja/libLIEF.so``

  - **Windows**:

    - ``C:\Users\romain\AppData\Roaming\Binary Ninja\plugins\LIEF.dll``
    - ``%APPDATA%\Binary Ninja\plugins\LIEF.dll``

:fa:`solid fa-bug` Troubleshooting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Plugin module failed to load**

.. code-block:: text

  [:0 Default] Plugin module '~/.binaryninja/plugins/lief-dwarf-plugin-linux-x86_64.so' failed to load
  [:0 Default] dlerror() reports: libLIEF.so: cannot open shared object file: No such file or directory

This means that ``libLIEF.so, libLIEF.dylib, or LIEF.dll`` is not correctly
installed in the ``plugins/`` directory. Make sure that the LIEF shared library is
next to the plugin that failed to load.

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
