01 - Parse and manipulate formats
---------------------------------

The objective of this tutorial is to give an overview of the LIEF's API to parse and manipulate formats

By Romain Thomas - `@rh0main <https://twitter.com/rh0main>`_

-----

ELF
~~~

We start by the ``ELF`` format. To create an :class:`.ELF.Binary` from a file we just have to give its path to the :func:`lief.parse` or :func:`lief.ELF.parse` functions

.. note::

  With the Python API, these functions have the same behaviour but in C++, :cpp:func:`LIEF::Parser::parse` will
  return a pointer to a :cpp:class:`LIEF::Binary` object whereas :cpp:func:`LIEF::ELF::Parser::parse` will return
  a :cpp:class:`LIEF::ELF::Binary` object

.. code-block:: python

  import lief
  binary = lief.parse("/bin/ls")

Once the ELF file has been parsed, we can access to its :class:`~lief.ELF.Header`:

.. code-block:: python

  header = binary.header

Change the entry point and the target architecture (:class:`~lief.ELF.ARCH`)

.. code-block:: python

  header.entrypoint = 0x123
  header.machine_type = lief.ELF.ARCH.AARCH64

and then rebuild it:

.. code-block:: python

  binary.write("ls.modified")

We can also iterate over binary :class:`~lief.ELF.Section`\s as follows:

.. code-block:: python

  for section in binary.sections:
    print(section.name) # section's name
    print(section.size) # section's size
    print(len(section.content)) # Should match the previous print


To modify the content of the ``.text`` section:

.. code-block:: python

  text = binary.get_section(".text")
  text.content = bytes([0x33] * text.size)


PE
~~~

As for the ``ELF`` part, we can use the :func:`lief.parse` or :func:`lief.PE.parse` functions to create a :class:`.PE.Binary`


.. code-block:: python

  import lief
  binary = lief.parse("C:\\Windows\\explorer.exe")


To access to the different PE headers (:class:`~lief.PE.DosHeader`, :class:`~lief.PE.Header` and :class:`~lief.PE.OptionalHeader`):

.. code-block:: python

  print(binary.dos_header)
  print(binary.header)
  print(binary.optional_header)

One can also access to the imported functions using two methods. The abstract one which will the use the LIEF abstract layer:

.. code-block:: python

  for func in binary.imported_functions:
    print(func)

To have a better granularity on the location of the imported function in libraries or to access to other fields of the PE imports:

.. code-block:: python

  for imported_library in binary.imports:
    print("Library name: " + imported_library.name)
    for func in imported_library.entries:
      if not func.is_ordinal:
        print(func.name)
      print(func.iat_address)

LIEF enables to modify all the properties of the :class:`~lief.PE.Import` and :class:`~lief.PE.ImportEntry` but to take account of the modification, the :class:`~lief.PE.Builder` must be
configured as follow:

.. code-block:: python

  builder = lief.PE.Builder(binary)
  builder.build_imports(True)
  builder.patch_imports(True)

  builder.build()
  builder.write("result.exe")













