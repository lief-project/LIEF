.. _02-pe-from-scratch:

02 - Create a PE from scratch
-----------------------------

In this tutorial we introduce LIEF API to create a simple PE executable from scratch

Scripts and materials are available here: `materials <https://github.com/lief-project/tutorials/tree/master/02_PE_from_Scratch>`_


By Romain Thomas - `@rh0main <https://twitter.com/rh0main>`_

----------

LIEF enables creating a simple PE from scratch.
The aim of this tutorial is to create an executable which shows a "Hello Word" ``MessageBoxA``.

First, we have to create a :class:`~lief.PE.Binary` :


.. code-block:: python

  from lief import PE

  binary32 = PE.Binary("pe_from_scratch", PE.PE_TYPE.PE32)

The first parameter is the binary's name and the second, the binary's type: ``PE32`` or ``PE32_PLUS`` (see :class:`~lief.PE.PE_TYPE`).
The :class:`~lief.PE.Binary`'s constructor creates automatically :class:`~lief.PE.DosHeader`, :class:`~lief.PE.Header`, :class:`~lief.PE.OptionalHeader` an empty :class:`~lief.PE.DataDirectory`.

Now that we have a minimal binary, we have to add sections. We will have a first section holding assembly code (``.text``) and a second one containing strings (``.data``):

.. code-block:: python

  section_text                 = PE.Section(".text")
  section_text.content         = code
  section_text.virtual_address = 0x1000

  section_data                 = PE.Section(".data")
  section_data.content         = data
  section_data.virtual_address = 0x2000

A ``MessageBoxA`` is composed of a title and a message. These two strings can be stored in the ``.data`` as follows:

.. code-block:: python

  title   = "LIEF is awesome\0"
  message = "Hello World\0"

  data =  list(map(ord, title))
  data += list(map(ord, message))

The **pseudo** assembly code of the ``.text`` section is given in next listing:

.. code-block:: nasm

    push 0x00              ; uType
    push "LIEF is awesome" ; Title
    push "Hello World"     ; Message
    push 0                 ; hWnd
    call MessageBoxA       ;
    push 0                 ; uExitCode
    call ExitProcess       ;


Instead of pushing strings we have to push the **virtual address** of these strings. In the PE format a section's virtual address is in fact a **relative** virtual address (relative to :attr:`.OptionalHeader.imagebase` when the ASLR is not enabled). By default the :class:`~lief.PE.Binary`'s constructor sets the :attr:`~lief.PE.OptionalHeader.imagebase` to ``0x400000``.

As a result, the virtual addresses of the strings are:

  * **title**: :attr:`~lief.PE.OptionalHeader.imagebase` + :attr:`~lief.PE.Section.virtual_address` + 0 = ``0x402000``
  * **message**: :attr:`~lief.PE.OptionalHeader.imagebase` + :attr:`~lief.PE.Section.virtual_address` + ``len(title)`` = ``0x402010``

.. code-block:: nasm

    push 0x00              ; uType
    push 0x402000          ; Title
    push 0x402010          ; Message
    push 0                 ; hWnd
    call MessageBoxA       ;
    push 0                 ; uExitCode
    call ExitProcess       ;

As the code uses ``MessageBoxA``, we need to import ``user32.dll`` into the binary's :class:`~lief.PE.Import`\s and the ``MessageBoxA`` :class:`~lief.PE.ImportEntry`.
To do so, we can use the :meth:`~lief.PE.Binary.add_library` method combined with :meth:`~lief.PE.Import.add_entry`:

.. code-block:: python

  user32 = binary32.add_library("user32.dll")
  user32.add_entry("MessageBoxA")

Same for ``ExitProcess`` (``kernel32.dll``):

.. code-block:: python

  kernel32 = binary32.add_library("kernel32.dll")
  kernel32.add_entry("ExitProcess")

Once needed libraries and functions are added to the binary, we have to determine their addresses (**I**\mport **A**\ddress **T**\able).

For that, we can use the :meth:`~lief.PE.Binary.predict_function_rva` method which will return the ``IAT`` address set by the :class:`~lief.PE.Builder`:


.. automethod:: lief.PE.Binary.predict_function_rva
  :noindex:


.. code-block:: python

  ExitProcess_addr = binary32.predict_function_rva("kernel32.dll", "ExitProcess")
  MessageBoxA_addr = binary32.predict_function_rva("user32.dll", "MessageBoxA")
  print("Address of 'ExitProcess': 0x{:06x} ".format(ExitProcess_addr))
  print("Address of 'MessageBoxA': 0x{:06x} ".format(MessageBoxA_addr))


.. code-block:: console

  Address of 'ExitProcess': 0x00306a
  Address of 'MessageBoxA': 0x00305c

Thus, the **absolute** virtual addresses of ``MessageBoxA`` and ``ExitProcess`` are:

  * ``MessageBoxA``: :attr:`~lief.PE.OptionalHeader.imagebase` + ``0x306a`` = ``0x40306a``
  * ``ExitProcess``: :attr:`~lief.PE.OptionalHeader.imagebase` + ``0x305c`` = ``0x40305c``

And the associated assembly code:

.. code-block:: nasm

    push 0x00              ; uType
    push 0x402000          ; Title
    push 0x402010          ; Message
    push 0                 ; hWnd
    call 0x40306a          ;
    push 0                 ; uExitCode
    call 0x40305c          ;


The transformation of the :class:`~lief.PE.Binary` into an executable is performed by the :class:`~lief.PE.Builder` class.

By default the import table is not rebuilt so we have to configure the builder to rebuild it:

.. code-block:: python

  builder = lief.PE.Builder(binary32)
  builder.build_imports(True)
  builder.build()
  builder.write("pe_from_scratch.exe")


You can now enjoy the newly created binary.












