.. _plugins-binaryninja-analyzers-android-jni:

:fa:`solid fa-object-ungroup` Android JNI
-----------------------------------------

This analyzer improves support for JNI functions in Android native
libraries. It works by providing a BinaryNinja type library ``android-jni.bntl``
which is placed next to the plugin's shared library:

.. code-block:: text

  .
  ├── lief-analysis-plugin-linux-x86_64.so
  ├── lief-dwarf-plugin-linux-x86_64.so
  └── typelib
      └── aarch64
          └── android-jni.bntl

This type library should be installed in one of the following locations:

* **Linux:** ``~/.binaryninja/typelib/aarch64/android-jni.bntl``
* **Windows:** ``C:\Users\romain\AppData\Roaming\Binary Ninja\typelib\aarch64\android-jni.bntl``
* **macOS:** ``~/Library/Application Support/Binary Ninja/typelib/aarch64/android-jni.bntl``

After installation, select ``Plugins > LIEF > Enhance Analysis``, the
plugin will then import all types related to Android JNI.

In addition, it will automatically define the type for the ``JNI_OnLoad``
function:

.. img-comparison::
  :left: img/before.svg
  :right: img/after.svg

Functions that are tagged [#f1]_ with ``"LIEF - Android JNI Function"`` are also
updated to expose the correct type in the first two arguments:

.. img-comparison::
  :left: img/before_java.svg
  :right: img/after_java.svg

.. include:: ../../../../../_cross_api.rst

.. [#f1] On a given function, right click: ``Tags and Bookmarks > Add Tag ... > LIEF - Android JNI Function``
