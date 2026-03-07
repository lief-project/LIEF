09 - How to use Frida on a non-rooted device
--------------------------------------------

In this tutorial, we will see how to use the Frida gadget on a non-rooted device.

------

In recent years, Frida has become the standard tool for performing hooking. It
supports various platforms and enables writing hooks quickly and dynamically.

Most of the time, there are no constraints on using Frida on a rooted device,
but in some scenarios, the application being analyzed might check its
environment.

A technique based on modifying the Dalvik bytecode has been well-described by
`@ikoz <https://twitter.com/ikoz>`_ in the post "`Using Frida on Android without root <https://koz.io/using-frida-on-android-without-root/>`_". In this tutorial,
we propose a new technique that does not require modifying the Dalvik
bytecode (i.e., ``classes.dex``).

Frida Gadget
~~~~~~~~~~~~

In its default mode, Frida first needs to inject an *agent* into the targeted
application so that it resides in the process's memory space.

On Android and Linux, this injection is typically performed with ``ptrace`` by
attaching to or spawning a process and then injecting the agent. Once the agent
is injected, it communicates with its server through a pipe.

Some types of injection require privileges. For example, a *normal* user
cannot use ``ptrace``. To address this constraint, Frida provides another mode
of operation called "embedded". In this mode, the user is responsible for
injecting the *frida-gadget* library.

Such injection can be performed using:

* Environment variables: ``LD_PRELOAD``, ``DYLD_INSERT_LIBRARIES``, etc.
* Using ``dlopen``.
* In an open-source target, using the linker to link with the Frida gadget.
* ...

For more information about the Frida gadget, refer to the documentation:
`frida-gadget <https://frida.re/docs/gadget/>`_

Frida & LIEF
~~~~~~~~~~~~

One less-known but established injection technique is based on modifying the
ELF format. This was well-explained by Mayhem in
`Phrack <http://phrack.org/issues/61/8.html>`_ [1]_, and LIEF provides a
user-friendly API [2]_ to perform it.

To summarize, executable formats include libraries that are linked with the
executable. We can obtain a list of linked libraries using ``ldd`` or
``readelf`` (Unix) or with `elf_reader.py <https://github.com/lief-project/LIEF/blob/main/examples/python/elf_reader.py>`_ (Linux, Windows, OSX):

.. code-block:: console

  $ python ./elf_reader.py -d /bin/ls

  == Dynamic entries ==

  |Tag    | Value | Info        |
  |NEEDED | 0x1   | libcap.so.2 |
  |NEEDED | 0x80  | libc.so.6   |

Here, ``/bin/ls`` has two dependencies:

* ``libcap.so.2``
* ``libc.so.6``

During the loading phase of the executable, the loader iterates over these
libraries and maps them into the process's memory space. Once mapped, it calls
their constructors [3]_.

The idea is to add ``frida-agent.so`` as a dependency of native libraries
embedded in the APK.

Adding such a dependency is as simple as:

.. code-block:: python

  import lief

  libnative = lief.parse("libnative.so")
  libnative.add_library("libgadget.so") # Injection!
  libnative.write("libnative.so")

Telegram
~~~~~~~~

To illustrate the process, we will inject the Frida gadget into the Telegram
application. It is an interesting target because:

* It contains only one native library, so the library will be loaded early.
* It demonstrates LIEF's reliability in modifying ELF files.
* It is a real-world application.


Regarding the environment, we will use Telegram version ``4.8.4-12207``
(February 18, 2018) on an Android 6.0.1 device with an AArch64 architecture
(Samsung Galaxy S6).

Injection with LIEF
###################

As explained above, the injection is simply a call to
:meth:`lief.ELF.Binary.add_library` on the ``libtmessages.28.so`` library.

Prior to injection, ``libtmessages.28.so`` is linked against the following
libraries:

.. code-block:: bash

  $ readelf -d ./libtmessages.28.so|grep NEEDED
    0x0000000000000001 (NEEDED) Shared library: [libjnigraphics.so]
    0x0000000000000001 (NEEDED) Shared library: [liblog.so]
    0x0000000000000001 (NEEDED) Shared library: [libz.so]
    0x0000000000000001 (NEEDED) Shared library: [libOpenSLES.so]
    0x0000000000000001 (NEEDED) Shared library: [libEGL.so]
    0x0000000000000001 (NEEDED) Shared library: [libGLESv2.so]
    0x0000000000000001 (NEEDED) Shared library: [libdl.so]
    0x0000000000000001 (NEEDED) Shared library: [libstdc++.so]
    0x0000000000000001 (NEEDED) Shared library: [libm.so]
    0x0000000000000001 (NEEDED) Shared library: [libc.so]

After ``telegram.add_library("libgadget.so")``, the new dependency is at the
first position:

.. code-block:: bash

  $ readelf -d ./libtmessages.28.so|grep NEEDED
    0x0000000000000001 (NEEDED) Shared library: [libgadget.so]
    0x0000000000000001 (NEEDED) Shared library: [libjnigraphics.so]
    0x0000000000000001 (NEEDED) Shared library: [liblog.so]
    0x0000000000000001 (NEEDED) Shared library: [libz.so]
    0x0000000000000001 (NEEDED) Shared library: [libOpenSLES.so]
    0x0000000000000001 (NEEDED) Shared library: [libEGL.so]
    0x0000000000000001 (NEEDED) Shared library: [libGLESv2.so]
    0x0000000000000001 (NEEDED) Shared library: [libdl.so]
    0x0000000000000001 (NEEDED) Shared library: [libstdc++.so]
    0x0000000000000001 (NEEDED) Shared library: [libm.so]
    0x0000000000000001 (NEEDED) Shared library: [libc.so]



Configuring the Frida Gadget
#############################

According to the documentation, the Frida gadget allows the use of a
configuration file to parameterize interaction:

* **Listing**: Interaction is the same as frida-server.
* **Script**: Direct interaction with a JS script at a specified path.
* **ScriptDirectory**: Same as *Script*, but for multiple applications and scripts.

The *Listing* interaction would require the ``android.permission.INTERNET``
permission. While we could add this permission by modifying the manifest,
we will use the *Script* interaction instead, as it does not require additional
permissions.

The Frida payload will be located in the ``/data/local/tmp/myscript.js`` file.
The gadget configuration for this context is provided below:

.. code-block:: json

  {
    "interaction": {
      "type": "script",
      "path": "/data/local/tmp/myscript.js",
      "on_change": "reload"
    }
  }

Using a configuration file must follow two requirements:

1. The file must have the same name as the gadget library (e.g., ``libgadget.so`` and ``libgadget.conf``).
2. The configuration file must be located in the **same** directory as the gadget library.

The second requirement means that after installation on the device, the gadget
library will look for the configuration file in the
``/data/app/org.telegram.messenger-1/lib`` directory.

When installing an application, the Android package manager copies files from
the ``lib/`` directory of the APK only if [4]_:

* They start with the prefix ``lib``.
* They end with the suffix ``.so``.
* It is ``gdbserver``.

Frida is aware of these requirements, as illustrated in the listing below.
Hence, we can simply add the ``.so`` suffix to ``libgadget.conf``:

.. code-block:: cpp

  #if ANDROID
    if (!FileUtils.test (config_path, FileTest.EXISTS)) {
      var ext_index = config_path.last_index_of_char ('.');
      if (ext_index != -1) {
        config_path = config_path[0:ext_index] + ".config.so";
      } else {
        config_path = config_path + ".config.so";
      }
    }
  #endif

.. rst-class:: center

`lib/gadget/gadget.vala <https://github.com/frida/frida-core/blob/289a08b237eeab1fb8ec3e2f41ed726de44b5d66/lib/gadget/gadget.vala#L500-L509>`_

Finally, the ``lib`` directory of the new Telegram ``.apk`` has the following
structure:

.. code-block:: bash

  $ tree lib
  .
  └── arm64-v8a
      ├── libgadget.config.so
      ├── libgadget.so
      └── libtmessages.28.so

With ``libtmessages.28.so`` linked against ``libgadget.so``:

.. code-block:: bash

  $ readelf -d ./arm64-v8a/libtmessages.28.so
    0x0000000000000001 (NEEDED) Shared library: [libgadget.so]
    ...



Run
####

Once:

1. The injection is performed in ``libtmessages.28.so``.
2. The gadget library and its configuration are placed in the ``/lib/ABI`` directory.
3. The application is resigned.

We can install the repackaged APK (``new.apk``) and push ``myscript.js`` to
``/data/local/tmp``:

.. code-block:: console

  $ adb shell install new.apk
  $ adb push myscript.js /data/local/tmp
  $ adb shell chmod 777 /data/local/tmp/myscript.js

The Frida script ``myscript.js`` used in this tutorial simply calls the Android
log function:

.. code-block:: javascript

  'use strict';

  console.log("Waiting for Java..");

  Java.perform(function () {
    var Log = Java.use("android.util.Log");
    Log.v("frida-lief", "Have fun!");
  });

.. rst-class:: center

myscript.js


Lastly, we can run the Telegram application and observe the Android logs:

.. figure:: ../_static/tutorial/09/telegram.png
  :scale: 25%
  :align: center

.. code-block:: console

  $ adb logcat -s "frida-lief:V"
  --------- beginning of system
  --------- beginning of main
  03-24 17:23:51.908 10243 10243 V frida-lief: Have fun!


Conclusion
~~~~~~~~~~

This tutorial demonstrated how static format instrumentation and dynamic
instrumentation can be combined.

Here is a quick summary of the advantages and disadvantages of this technique:

:Advantages:

  * Does not require a rooted device.
  * Does not depend on frida-server.
  * Can be used to bypass some anti-Frida protections.
  * Does not modify ``AndroidManifest.xml`` or DEX files.

:Disadvantages:

  * Requires adding files to the APK.
  * Requires the application to have at least one native library.
  * Relies on the library being loaded early in the application execution.



.. rubric:: Notes

.. [1] Note that LIEF **does not** modify the :attr:`~lief.ELF.DynamicEntry.TAG.DEBUG` entry ...

.. [2] Modifying the ELF Dynamic section is not as simple as the API might suggest.

.. [3] In the ELF format, these are located in the :attr:`~lief.ELF.DynamicEntry.TAG.INIT_ARRAY` or :attr:`~lief.ELF.DynamicEntry.TAG.INIT` entries.

.. [4] For those interested, checks are performed in the ``framework_base/core/jni/com_android_internal_content_NativeLibraryHelper.cpp`` file.
       Notably, these checks on the prefix and suffix are only performed if the application is not *debuggable*.




.. rubric:: API

* :meth:`lief.ELF.Binary.add_library`
