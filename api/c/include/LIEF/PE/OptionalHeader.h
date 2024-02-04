/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef C_LIEF_PE_OPTIONAL_HEADER_H
#define C_LIEF_PE_OPTIONAL_HEADER_H
#include <inttypes.h>

#include "LIEF/PE/enums.h"
#include "LIEF/visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

enum LIEF_PE_DLL_CHARACTERISTICS {
  LIEF_PE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020, /**< ASLR with 64 bit address space. */
  LIEF_PE_DLL_CHARACTERISTICS_DYNAMIC_BASE          = 0x0040, /**< DLL can be relocated at load time. */
  LIEF_PE_DLL_CHARACTERISTICS_FORCE_INTEGRITY       = 0x0080, /**< Code integrity checks are enforced. */
  LIEF_PE_DLL_CHARACTERISTICS_NX_COMPAT             = 0x0100, /**< Image is NX compatible. */
  LIEF_PE_DLL_CHARACTERISTICS_NO_ISOLATION          = 0x0200, /**< Isolation aware, but do not isolate the image. */
  LIEF_PE_DLL_CHARACTERISTICS_NO_SEH                = 0x0400, /**< Does not use structured exception handling (SEH). No SEH handler may be called in this image. */
  LIEF_PE_DLL_CHARACTERISTICS_NO_BIND               = 0x0800, /**< Do not bind the image. */
  LIEF_PE_DLL_CHARACTERISTICS_APPCONTAINER          = 0x1000, /**< Image should execute in an AppContainer. */
  LIEF_PE_DLL_CHARACTERISTICS_WDM_DRIVER            = 0x2000, /**< A WDM driver. */
  LIEF_PE_DLL_CHARACTERISTICS_GUARD_CF              = 0x4000, /**< Image supports Control Flow Guard. */
  LIEF_PE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000  /**< Terminal Server aware. */
};

enum LIEF_PE_SUBSYSTEM {
  LIEF_PE_SUBSYSTEM_UNKNOWN                  = 0,  /**< An unknown subsystem. */
  LIEF_PE_SUBSYSTEM_NATIVE                   = 1,  /**< Device drivers and native Windows processes */
  LIEF_PE_SUBSYSTEM_WINDOWS_GUI              = 2,  /**< The Windows GUI subsystem. */
  LIEF_PE_SUBSYSTEM_WINDOWS_CUI              = 3,  /**< The Windows character subsystem. */
  LIEF_PE_SUBSYSTEM_OS2_CUI                  = 5,  /**< The OS/2 character subsytem. */
  LIEF_PE_SUBSYSTEM_POSIX_CUI                = 7,  /**< The POSIX character subsystem. */
  LIEF_PE_SUBSYSTEM_NATIVE_WINDOWS           = 8,  /**< Native Windows 9x driver. */
  LIEF_PE_SUBSYSTEM_WINDOWS_CE_GUI           = 9,  /**< Windows CE. */
  LIEF_PE_SUBSYSTEM_EFI_APPLICATION          = 10, /**< An EFI application. */
  LIEF_PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11, /**< An EFI driver with boot services. */
  LIEF_PE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12, /**< An EFI driver with run-time services. */
  LIEF_PE_SUBSYSTEM_EFI_ROM                  = 13, /**< An EFI ROM image. */
  LIEF_PE_SUBSYSTEM_XBOX                     = 14, /**< XBOX. */
  LIEF_PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16  /**< A BCD application. */
};

struct Pe_OptionalHeader_t {
  enum LIEF_PE_PE_TYPES  magic;
  uint8_t        major_linker_version;
  uint8_t        minor_linker_version;
  uint32_t       sizeof_code;
  uint32_t       sizeof_initialized_data;
  uint32_t       sizeof_uninitialized_data;
  uint32_t       addressof_entrypoint;
  uint32_t       baseof_code;
  uint32_t       baseof_data;
  uint64_t       imagebase;
  uint32_t       section_alignment;
  uint32_t       file_alignment;
  uint16_t       major_operating_system_version;
  uint16_t       minor_operating_system_version;
  uint16_t       major_image_version;
  uint16_t       minor_image_version;
  uint16_t       major_subsystem_version;
  uint16_t       minor_subsystem_version;
  uint32_t       win32_version_value;
  uint32_t       sizeof_image;
  uint32_t       sizeof_headers;
  uint32_t       checksum;
  enum LIEF_PE_SUBSYSTEM subsystem;
  uint32_t       dll_characteristics;
  uint64_t       sizeof_stack_reserve;
  uint64_t       sizeof_stack_commit;
  uint64_t       sizeof_heap_reserve;
  uint64_t       sizeof_heap_commit;
  uint32_t       loader_flags;
  uint32_t       numberof_rva_and_size;
};

typedef struct Pe_OptionalHeader_t Pe_OptionalHeader_t;

LIEF_API const char* lief_pe_subsytem_str(enum LIEF_PE_SUBSYSTEM e);

#ifdef __cplusplus
}
#endif

#endif
