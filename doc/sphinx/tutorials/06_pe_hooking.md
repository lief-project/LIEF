(06-pe-hooking)=

# 06 - PE Hooking (Deprecated)

:::{warning}
This tutorial is no longer functional as the PE hooking functions have been
removed from LIEF.
:::

The objective of this tutorial is to show how to hook imported functions.

______________________________________________________________________

The targeted binary is a simple `PE64` *HelloWorld* that prints the first
argument to the console:

```cpp
#include "stdafx.h"
#include <stdio.h>

int main(int argc, char** argv) {
  printf("Hello: %s\n", argv[1]);
  return 0;
}
```

```console
$ PE64_x86-64_binary_HelloWorld.exe World
$ Hello: World
```

Using LIEF, we will replace the function that prints the message to the console
with a `MessageBox`.

By disassembling the binary, we can see that the *print* occurs in the function
`sub_140001030`, which uses two external functions: `__acrt_iob_func` and
`__stdio_common_vfprintf`.

:::{figure} ../_static/tutorial/06/06_hooking_1.png
:align: center
:scale: 80 %
:::

:::{figure} ../_static/tutorial/06/06_hooking_2.png
:align: center
:scale: 80 %
:::

According to the Microsoft x64 calling convention, the format string is located
in the `rcx` register, and the input message is in the `rdx` register.

Basically, the {ref}`hooking-code` replaces the `__acrt_iob_func` function and
displays a `MessageBox` with the `rdx` message.

```{code-block} nasm
:caption: hooking code
:name: hooking-code

add rsp, 0x48         ; Stack unwind
xor rcx, rcx          ; hWnd
mov rdx, rdx          ; Message
mov r8,  0x0140009000 ; Title
xor r9, r9            ; MB_OK
mov rax, 0x014000A3E4 ; MessageBoxA address
call [rax]            ; MessageBoxA(hWnd, Message, Title, MB_OK)
xor rcx, rcx          ; exit value
mov rax, 0x014000A3d4 ; ExitProcess address
call [rax]            ; ExitProcess(0)
ret                   ; Never reached
```

:::{note}
As in tutorial {ref}`02-pe-from-scratch`, the addresses of `MessageBoxA`
and `ExitProcess` can be found using the function:
:::

First, we create the `.htext` section, which will hold the hooking code:

```python
section_text                 = lief.PE.Section(".htext")
section_text.content         = code
section_text.virtual_address = 0x7000
section_text.characteristics = lief.PE.Section.CHARACTERISTICS.CNT_CODE | lief.PE.Section.CHARACTERISTICS.MEM_READ | lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE

section_text = pe.add_section(section_text)
```

Next, we create the `.hdata` section for the `MessageBox` title:

```python
title   = "LIEF is awesome\0"
data =  list(map(ord, title))

section_data                 = lief.PE.Section(".hdata")
section_data.content         = data
section_data.virtual_address = 0x8000
section_data.characteristics = lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA | lief.PE.Section.CHARACTERISTICS.MEM_READ

section_data = pe.add_section(section_data)
```

Since ASLR is enabled, we will disable it to avoid dealing with relocations:

{{ literalinclude("../../code/python/tuto_pe_hooking.py", "disable-aslr") }}

We will also disable `NX` protection:

{{ literalinclude("../../code/python/tuto_pe_hooking.py", "disable-nx") }}

As `ExitProcess` is not imported in `KERNEL32.dll`, we need to add it:

{{ literalinclude("../../code/python/tuto_pe_hooking.py", "add-exitprocess") }}

The `MessageBoxA` function is located in `user32.dll`, so we must add it:

```python
user32 = binary.add_library("user32.dll")
user32.add_entry("MessageBoxA")
```

Then, we proceed to hook the `__acrt_iob_func` function:

```python
pe.hook_function("__acrt_iob_func", binary.optional_header.imagebase + section_text.virtual_address)
```

Finally, we configure the {class}`~lief.PE.Builder` to create a new import
table and patch the original one with trampolines.

```python
builder = lief.PE.Builder(binary)

builder.build_imports(True).patch_imports(True)

builder.build()

builder.write("lief_pe_hooking.exe")
```

Now we can run the final executable:

```console
$ lief_pe_hooking.exe "Hooking World"
```

:::{figure} ../_static/tutorial/06/06_hooking_3.png
:align: center
:scale: 80 %
:::

{{ cross_api }}
