09 - How to use frida on a non-rooted device
--------------------------------------------

In this tutorial we will see how to use Frida gadget on a non-rooted device.

Scripts and materials are available here: `materials <https://github.com/lief-project/tutorials/tree/master/09_Frida_LIEF>`_


By Romain Thomas - `@rh0main <https://twitter.com/rh0main>`_

------

From the last few years, Frida became the tool of the trade to perform hooking. It supports various platforms and
enables to write hooks quickly and dynamically.

Most of the time there are no constraints to use Frida on a rooted device but in some scenario the application to analyze could
check its environment.

A technique based on modifying the Dalvik bytecode has been well described by `@ikoz <https://twitter.com/ikoz>`_ in the post "`Using Frida on Android without root <https://koz.io/using-frida-on-android-without-root/>`_". In this tutorial we propose a new technique without modifying the Dalvik Bytecode (i.e. ``classes.dex``).

Frida Gadget
~~~~~~~~~~~~

In the default mode, Frida needs in a first step to inject an *agent* in the targeted application so that it is in the memory space of the process.

On Android and Linux such injection is done with ``ptrace`` by attaching or spawning a process and then injecting the agent.
Once the agent is injected, it communicates with its server through a pipe.

Some kind of injection require privileges. For example, we can't use ``ptrace`` as a *normal* user. To address this constraint, Frida provides another
mode of operation called "embedded". In this mode the user is responsible to inject the *frida-gadget* library.

Such injection could be done with:

* Environment variables: ``LD_PRELOAD``, ``DYLD_INSERT_LIBRARIES`` ...
* Using ``dlopen``
* In an open-source target, use the linker to link with frida-gadget.
* ...

For more information about Frida gadget, here is the documentation: `frida-gadget <https://frida.re/docs/gadget/>`_

Frida & LIEF
~~~~~~~~~~~~

One less known injection technique but quite old is based on modifying the ELF format. It has been well explained by Mayhem in `Phrack <http://phrack.org/issues/61/8.html>`_ [1]_ and LIEF provides a user-friendly API [2]_ to do it.

To summarize, executable formats include libraries that are linked with executable. We can have list of linked libraries with
``ldd`` or ``readelf`` (Unix) or with `elf_reader.py <https://github.com/lief-project/LIEF/blob/main/examples/python/elf_reader.py>`_ (Linux, Windows, OSX):

.. code-block:: console

  $ python ./elf_reader.py -d /bin/ls

  == Dynamic entries ==

  |Tag    | Value | Info        |
  |NEEDED | 0x1   | libcap.so.2 |
  |NEEDED | 0x80  | libc.so.6   |

Here ``/bin/ls`` has two dependencies:

* ``libcap.so.2``
* ``libc.so.6``

In the loading phase of the executable, the loader iterates over these libraries and map them in the memory space of the process. Once mapped it calls its constructor [3]_.

The idea is to add ``frida-agent.so`` as a dependency of native libraries embedded in the APK.

Adding such dependencies is as simple as:

.. code-block:: python

  import lief

  libnative = lief.parse("libnative.so")
  libnative.add_library("libgadget.so") # Injection!
  libnative.write("libnative.so")

Telegram
~~~~~~~~

To explain the process, we will inject frida gadget in the Telegram application. It's an interesting target because:

* It contains only one native library so the library should be loaded early.
* It shows the reliability of LIEF to modify ELF files
* It's a real app


Regarding the environment, we will use the version ``4.8.4-12207`` of Telegram (February 18, 2018) on an Android 6.0.1 device with an AArch64 architecture (Samsung Galaxy S6)

Injection with LIEF
###################

As explained above, the injection is just a call to the :meth:`lief.ELF.Binary.add_library` on the ``libtmessages.28.so`` library.

Prior to the injection ``libtmessages.28.so`` is linked against the following libraries

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

After ``telegram.add_library("libgadget.so")`` we have the new dependency at the first position:

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



Configuration of Frida Gadget
#############################

From the documentation, Frida gadget enables to use a configuration file to parametrize the interaction:

* **Listing**: Interaction is the same as frida-server
* **Script**: Direct interaction with a JS script for which the path is specified in the configuration
* **ScriptDirectory**: Same as *Script* but for multiple applications and multiple scripts

*Listing* interaction would require ``android.permission.INTERNET`` permission. We can add such permission by modifying the manifest. Instead, we will use the *Script* interaction which does not require permission.

The Frida payload will be located in ``/data/local/tmp/myscript.js`` file. The gadget configuration associated with context is given below

.. code-block:: json

  {
    "interaction": {
      "type": "script",
      "path": "/data/local/tmp/myscript.js",
      "on_change": "reload"
    }
  }

Use of configuration file must follow two requirements:

1. File must have the same name as the gadget library name (e.g. ``libgadget.so`` and ``libgadget.conf``)
2. The configuration file must be located in the **same** directory as the gadget library

The second requirement means that after the installation on the device, the gadget library will look for the config file in the ``/data/app/org.telegram.messenger-1/lib`` directory.

When installing an application, the Android package manager will copy files from the ``lib/`` directory of the APK only if [4]_:

* It starts with the prefix ``lib``
* It ends with the suffix ``.so``
* It's ``gdbserver``

Frida is aware of these requirements as illustrated in listing below. Hence we can simply add the suffix ``.so`` to ``libgadget.conf``

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

Finally, the ``lib`` directory of the new Telegram ``.apk`` has the following structure:

.. code-block:: bash

  $ tree lib
  .
  └── arm64-v8a
      ├── libgadget.config.so
      ├── libgadget.so
      └── libtmessages.28.so

With ``libtmessages.28.so`` linked with ``libgadget.so``

.. code-block:: bash

  $ readelf -d ./arm64-v8a/libtmessages.28.so
    0x0000000000000001 (NEEDED) Shared library: [libgadget.so]
    ...



Run
####

Once:

1. The injection done in ``libtmessages.28.so``
2. The gadget library and its configuration placed in the ``/lib/ABI`` directory
3. The application resigned

We can install the repackaged APK ``new.apk`` and push ``myscript.js`` in ``/data/local/tmp``:

.. code-block:: console

  $ adb shell install new.apk
  $ adb push myscript.js /data/local/tmp
  $ adb shell chmod 777 /data/local/tmp/myscript.js

The Frida script ``myscript.js`` used in this tutorial is just a call to the Android log function:

.. code-block:: javascript

  'use strict';

  console.log("Waiting for Java..");

  Java.perform(function () {
    var Log = Java.use("android.util.Log");
    Log.v("frida-lief", "Have fun!");
  });

.. rst-class:: center

myscript.js


Lastly, we can run the telegram application and observe the Android logs:

.. figure:: ../_static/tutorial/09/telegram.png
  :scale: 25%
  :align: center

.. code-block:: console

  $ adb logcat -s "frida-lief:V"
  --------- beginning of system
  --------- beginning of main
  03-24 17:23:51.908 10243 10243 V frida-lief: Have Fun!


Conclusion
~~~~~~~~~~

With this tutorial we demonstrated how format instrumentation and dynamic instrumentation can be combined.

Here is a quick summary of advantages/disadvantages of this technique

:Advantages:

  * Doesn't require rooted device
  * Doesn't depend of frida-server
  * Can be used to bypass some anti-frida
  * Doesn't modify ``AndroidManifest.xml`` and DEX file(s)

:Disadvantages:

  * Require to add files in the APK
  * Require that the application have at least one native library
  * Hope that the library is loaded early in the application



.. rubric:: Notes

.. [1] Note that LIEF **does not** modify the :attr:`~lief.ELF.DynamicEntry.TAG.DEBUG` entry ...

.. [2] Modification of the ELF Dynamic section is not as easy as the API looks like.

.. [3] In the ELF format they are located in the :attr:`~lief.ELF.DynamicEntry.TAG.INIT_ARRAY` or :attr:`~lief.ELF.DynamicEntry.TAG.INIT` entries

.. [4] For those who are interested, checks are done in the ``framework_base/core/jni/com_android_internal_content_NativeLibraryHelper.cpp`` file.
       Actually these checks on the prefix and suffix are only done if the application is not *debuggable*.




.. rubric:: API

* :meth:`lief.ELF.Binary.add_library`









