.. _binary-abstraction:

:fa:`brands fa-uncharted` Binary Abstraction
-----------------------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

:ref:`ELF <format-elf>`, :ref:`PE <format-pe>`, :ref:`Mach-O <format-macho>`
binaries share similar characteristics, such as an entry point, imported/exported
functions, etc.

These shared characteristics are represented in an *abstract* layer, which is
defined by an inheritance relationship in C++/Python and by a trait in Rust.

Specifically, |lief-elf-binary|, |lief-pe-binary|, and |lief-macho-binary|
either inherit or implement the trait: |lief-abstract-binary|.

In Python/C++, one can access an *abstract* binary object by using the generic
|lief-abstract-parse| function:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        target: lief.Binary = lief.parse("/tmp/some.elf")

        target: lief.Binary = lief.parse("/Users/demo/some.macho")

        target: lief.Binary = lief.parse(r"C:\some.pe.exe")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse("some.elf");

        std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse("some.macho");

        std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse("some.exe");

Due to Python's dynamic polymorphism, the return value of
:py:func:`lief.parse` is automatically cast into either:
:class:`lief.ELF.Binary`, :class:`lief.PE.Binary`, or :class:`lief.MachO.Binary`.
To **upcast** this object into a :class:`lief.Binary` object, one can use the
:attr:`lief.Binary.abstract` attribute, which returns a :class:`lief.Binary`
instance:

.. code-block:: python

   import lief

   target = lief.parse("some.elf")
   assert type(target) is lief.ELF.Binary

   abstract = target.abstract
   assert type(abstract) is lief.Binary

In C++, a :cpp:class:`LIEF::Binary` instance can be **downcast** to its underlying
type using the ``classof`` idiom:

.. code-block:: cpp

   std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse("some.elf");

   if (LIEF::ELF::Binary::classof(target.get())) {
     auto& elf = static_cast<LIEF::ELF::Binary&>(*target);
   }

.. seealso::

  - :cpp:func:`LIEF::ELF::Binary::classof`
  - :cpp:func:`LIEF::PE::Binary::classof`
  - :cpp:func:`LIEF::MachO::Binary::classof`

.. include:: ../../_cross_api.rst
