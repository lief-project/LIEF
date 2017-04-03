01 - Parse and manipulate formats
---------------------------------

The objective of this tutorial is to give an overview of the LIEF's API to parse and manipulate formats

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











