.. _plugins-ghidra-dwarf:

:fa:`solid fa-dragon` Ghidra - DWARF Plugin
-------------------------------------------

Export as DWARF
~~~~~~~~~~~~~~~

This functionality exports Ghidra's Program information into a DWARF file.
This exported information include function's names, types, stack variables etc.

You can use this extension in different ways as documented below:

Project Manager
###############

This extension provides a DWARF exporter that can be used by right clicking
on the binary to export, then: ``Export > Format > DWARF``:

.. raw:: html

  <img style="max-width: 70%;" src="../../../_static/ghidra/project-dwarf-export.webp" alt="Ghidra DWARF exporter" />
  <br />
  <br />

CodeBrowser
###########

From the ``CodeBrowser`` tool, you can left click on the LIEF menu and select
``Export as DWARF``:

.. raw:: html

  <img style="max-width: 70%;" src="../../../_static/ghidra/codebrowser-export-dwarf.webp" alt="Ghidra DWARF exporter" />
  <br />
  <br />

Scripts
#######

You can also use the Java API from a (headless) script to export a given
Ghidra's Program:

.. code-block:: java

  import lief.ghidra.core.dwarf.export.Manager;
  import lief.ghidra.core.NativeBridge;

  public class LiefDwarfExportScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
      NativeBridge.init();
      Manager manager = new Manager(currentProgram);
      File output = new File("/home/romain/output.dwarf");
      manager.export(output);
    }
  }

Support & Limitations
#####################

This extension tries to convert as much as possible Ghidra's internal binary
representation into DWARF structures, but this support can't be exhaustive
so here is an overview of what is exported and what is not.

**ghidra.program.model.listing.Program**

- :fa-check:`check` Function
- :fa-check:`check` Data Variables
- :fa-check:`check` Types
- :xmark:`mark` Comments

**ghidra.program.model.listing.Function**

- :fa-check:`check` Name
- :fa-check:`check` Addresses range
- :fa-check:`check` Parameters
- :fa-check:`check` Type of parameters
- :fa-check:`check` Return type
- :fa-check:`check` Stack variables
- :fa-check:`check` Types of stack variables
- :xmark:`mark` Comments
- :xmark:`mark` CodeUnits

**ghidra.program.model.listing.Data**

- :fa-check:`check` Name
- :fa-check:`check` Type
- :fa-check:`check` Address
- :xmark:`mark` Comments

**ghidra.program.model.data.DataType**

- :fa-check:`check` ``ghidra.program.model.data.VoidDataType``
- :fa-check:`check` ``ghidra.program.model.data.AbstractIntegerDataType``
- :fa-check:`check` ``ghidra.program.model.data.Array``
- :fa-check:`check` ``ghidra.program.model.data.TypeDef``
- :fa-check:`check` ``ghidra.program.model.data.Composite``
- :fa-check:`check` ``ghidra.program.model.data.Enum``
- :fa-check:`check` ``ghidra.program.model.data.FunctionDefinition``
- :fa-check:`check` ``ghidra.program.model.data.Pointer``

Any types not mentioned here are not supported.

References
##########

https://github.com/NationalSecurityAgency/ghidra/issues/2687
