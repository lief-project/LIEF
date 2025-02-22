#if defined (WIN32) || defined(_MSC_VER)
#include <windows.h>
#include <WinBase.h>
#include <minwindef.h>
#endif

#if defined (__linux__)
#include <elf.h>
#include <link.h>
#endif

#if defined (__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#endif

#include "LIEF/LIEF.hpp"

int main() {
  return 0;
}
