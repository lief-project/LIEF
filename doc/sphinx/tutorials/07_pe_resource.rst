07 - PE Resources
-----------------

This tutorial provides an overview of the resource structure in a PE file and
explains how to manipulate it using LIEF.

------

Unlike the **ELF** and **Mach-O** formats, **PE** enables embedding *resources*
(icons, images, dialogs, etc.) within an executable or a DLL.

These resources are usually located in the ``.rsrc`` section, but this is not
an absolute rule.

To retrieve the section where resources are located, you can use the
:attr:`~lief.PE.DataDirectory.section` attribute of the associated
:class:`~lief.PE.DataDirectory`:

.. code-block:: python

  binary = lief.parse("C:\\Windows\\explorer.exe")
  if binary.has_resources:
    rsrc_directory = binary.data_directory(lief.PE.DataDirectory.TYPES.RESOURCE_TABLE)
    if rsrc_directory.has_section:
      print(rsrc_directory.section)

.. code-block:: console

  .rsrc     22e0d8    23f000    22e200    236c00    0         4.3596    CNT_INITIALIZED_DATA - MEM_READ

Resource Structure
******************

The underlying structure used to represent resources is a tree:

.. figure:: ../_static/tutorial/07/07_resource_tree.png
  :align: center

In the resource tree, there are basically two kinds of nodes:

#. :class:`~lief.PE.ResourceDirectory`: Contains information about the subtree.
#. :class:`~lief.PE.ResourceData`: Used to store raw data. These nodes are the **leaves** of the tree.

The first three levels of the tree have a special meaning:

* Level 1: The :attr:`~lief.PE.ResourceDirectory.id` represents the :class:`~lief.PE.ResourcesManager.TYPE`.
* Level 2: The :attr:`~lief.PE.ResourceDirectory.id` represents an ID for accessing the resource.
* Level 3: The :attr:`~lief.PE.ResourceDirectory.id` represents the :class:`~lief.PE.RESOURCE_LANGS` / SUBLANG of the resource.


You can check if a given binary embeds resources using the
:attr:`~lief.PE.Binary.has_resources` property. You can then access this
structure through the :attr:`~lief.PE.Binary.resources` property, which returns
a :class:`~lief.PE.ResourceDirectory` representing the **root** of the tree.

Given a :class:`~lief.PE.ResourceDirectory`, the
:attr:`~lief.PE.ResourceDirectory.childs` property returns an **iterator**
(similar to a ``list``) over the subtree associated with the node.

The following snippet retrieves the :attr:`~lief.PE.ResourcesManager.TYPE.MANIFEST`
element and prints it:

.. code-block:: python

  filezilla = lief.parse("filezilla.exe")

  if not filezilla.has_resources:
      print("'{}' has no resources. Abort!".format(filezilla.name), file=sys.stderr)
      sys.exit(1)

  root = filezilla.resources

  # First level => Type (ResourceDirectory node)
  manifest_node = next(i for i in root.childs if i.id == lief.PE.ResourcesManager.TYPE.MANIFEST)
  print(manifest_node)

  # Second level => ID (ResourceDirectory node)
  id_node = manifest_node.childs[0]
  print(id_node)

  # Third level => Lang (ResourceData node)
  lang_node = id_node.childs[0]
  print(lang_node)

  manifest = bytes(lang_node.content).decode("utf8")

  print(manifest)

.. code-block:: console

  [DIRECTORY] - ID: 0x18 - Depth: 1 - Childs : 1
      Characteristics :         0
      Time/Date stamp :         0
      Major version :           0
      Minor version :           0
      Number of name entries :  0
      Number of id entries :    1

  [DIRECTORY] - ID: 0x01 - Depth: 2 - Childs : 1
      Characteristics :         0
      Time/Date stamp :         0
      Major version :           0
      Minor version :           0
      Number of name entries :  0
      Number of id entries :    1

  [DATA] - ID: 0x409 - Depth: 3 - Childs : 0
      Code page :  0
      Reserved :   0
      Size :       1666
      Hash :       ffffffffb00b5419

  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <assemblyIdentity
      name="FileZilla"
  ...


Since manipulating a tree directly can be inconvenient, LIEF exposes a
:class:`~lief.PE.ResourcesManager`, which provides an enhanced API for
manipulating binary resources.


Resource Manager
****************

As mentioned previously, the :class:`~lief.PE.ResourcesManager` acts as a
wrapper around the resource tree to:

* Parse resources with predefined structures, such as
  :attr:`~lief.PE.ResourcesManager.TYPE.MANIFEST`, :attr:`~lief.PE.ResourcesManager.TYPE.ICON`, :attr:`~lief.PE.ResourcesManager.TYPE.VERSION`, etc.
* Access and modify these structures.

This can be summarized with the following diagram:

.. figure:: ../_static/tutorial/07/07_pe_resource_manager.png
  :align: center


The :class:`~lief.PE.ResourcesManager` can be accessed via the
:attr:`~lief.PE.Binary.resources_manager` property. To get an overview of the
binary's resources, you can simply *print* the :class:`~lief.PE.ResourcesManager`
instance:


.. code-block:: python

  filezilla = lief.parse("filezilla.exe")

  resource_manager = filezilla.resources_manager
  print(resource_manager)

.. literalinclude:: ../_static/tutorial/07/resource_manager_output.txt

Similar to the previous example, accessing the
:attr:`~lief.PE.ResourcesManager.TYPE.MANIFEST` element is as simple as:


.. code-block:: python

  filezilla = lief.parse("filezilla.exe")

  resources_manager = filezilla.resources_manager

  if not resources_manager.has_manifest:
      print("'{}' has no manifest. Abort!".format(filezilla.name), file=sys.stderr)
      sys.exit(1)

  manifest = resources_manager.manifest
  print(manifest)


Playing with the Manifest
*************************

Now we will see how to use the :class:`~lief.PE.ResourcesManager` to grant
*Administrator* privileges to an executable using the
:attr:`~lief.PE.RESOURCE_TYPES.MANIFEST` element.

The application manifest is implemented as an XML document; its documentation
is available here: `MSDN <https://docs.microsoft.com/en-us/windows/win32/sbscs/manifest-files-reference>`_

Among these tags, the ``requestedExecutionLevel`` tag *"describes the minimum
security permissions required for the application to run on the client
computer."* [#f1]_

.. code-block:: xml

  <requestedPrivileges>
    <requestedExecutionLevel level="..." uiAccess="..."/>
  </requestedPrivileges>

This tag has the following options:

* **Level**: Indicates the security level the application is requesting.

  * ``asInvoker``: Same permissions as the process that started it.
  * ``highestAvailable``: The application will run with the highest permission level possible.
  * ``requireAdministrator``: The application will run with administrator permissions.

* **uiAccess** (Optional): Indicates whether the application requires access to protected user interface elements.

  * ``true``
  * ``false``

Using :class:`~lief.PE.ResourcesManager`, replacing the ``asInvoker`` value
with ``requireAdministrator`` is straightforward:

.. code-block:: python

  filezilla = lief.parse("filezilla.exe")

  resources_manager = filezilla.resources_manager

  if not resources_manager.has_manifest:
      print("'{}' has no manifest. Abort!".format(filezilla.name), file=sys.stderr)
      sys.exit(1)

  manifest = resources_manager.manifest
  manifest = manifest.replace("asInvoker", "requireAdministrator")
  resources_manager.manifest = manifest

The PE :class:`~lief.PE.Builder` can be configured to rebuild the resource tree.
To apply the modifications, we must rebuild it:

.. warning::

  By default, the :class:`~lief.PE.Builder` does not rebuild the resource tree.

.. code-block:: python

  builder = lief.PE.Builder(filezilla)
  builder.build_resources(True)
  builder.build()
  builder.write("filezilla_rsrc.exe")


.. figure:: ../_static/tutorial/07/filezilla.png
  :scale: 90 %
  :align: center



Playing with Icons
******************

The :meth:`~lief.PE.ResourcesManager.change_icon` method switches icons between
two applications.

As in the previous section, obtain the :class:`~lief.PE.ResourcesManager` as
follows:

.. code-block:: python

  mfc = lief.parse("mfc.exe")
  cmd = lief.parse("cmd.exe")

  mfc_rsrc_manager = mfc.resources_manager
  cmd_rsrc_manager = cmd.resources_manager

Then, switch the first icons of the applications:

.. code-block:: python

  mfc_icons = mfc_rsrc_manager.icons
  cmd_icons = cmd_rsrc_manager.icons
  for i in range(min(len(mfc_icons), len(cmd_icons))):
      mfc_rsrc_manager.change_icon(mfc_icons[i], cmd_icons[i])


The MFC icons before switching:

.. figure:: ../_static/tutorial/07/mfc.png
  :scale: 90 %
  :align: center


After the switch:

.. figure:: ../_static/tutorial/07/mfc_modified.png
  :scale: 90 %
  :align: center

.. rubric:: References

.. [#f1] https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2015/deployment/trustinfo-element-clickonce-application
