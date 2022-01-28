
Introduction
============

The purpose of this project is to provide a cross platform library which can parse, modify and abstract
``ELF``, ``PE``, ``MachO`` and Android formats.

Main features:

* Parser: LIEF can parse ``ELF``, ``PE``, ``MachO``, ``DEX``, ``OAT``, ``ART`` and ``VDEX``.
  Moreover it provides an user-friendly API to access format internals.
* Modify: LIEF enables to modify **some** parts of these formats.
* Abstract: Usually formats have common features like sections, symbols, entry point...
  LIEF tries to provide an abstraction over these characteristics.
* API: LIEF can be used in C++, Python and, to a lesser extent, in C

The global architecture looks like this:

.. image:: _static/architecture.png
   :alt: LIEF Architecture
   :align: center

|


In the architecture, each format has its own *namespace*, parser and builder.
The parser takes a binary, library... as input and decomposes in LIEF object.
For instance, the ``ELF`` format has segments, so ``ELF::Parser`` will parse segments to create ``ELF::Segment``.
In the ``ELF::Binary`` class we will have a list of ``ELF::Segment`` which can be modified (change type, size, content...).
Then the ``ELF::Builder`` will transform ``ELF::Binary`` into a valid executable.
