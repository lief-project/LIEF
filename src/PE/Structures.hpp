/* Copyright 2021 - 2022 R. Thomas
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
#ifndef LIEF_PE_STRUCTURES_H_
#define LIEF_PE_STRUCTURES_H_
#include <type_traits>
#include <map>

#include "LIEF/types.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {

//! Namespace related to the LIEF's PE module
//!
//! Some parts come from llvm/Support/COFF.h
namespace PE {

namespace details {

//! Sizes in bytes of various things in the COFF format.
namespace STRUCT_SIZES {
  enum {
    Header16Size                  = 20,
    Header32Size                  = 56,
    NameSize                      = 8,
    Symbol16Size                  = 18,
    Symbol32Size                  = 20,
    SectionSize                   = 40,
    RelocationSize                = 10,
    BaseRelocationBlockSize       = 8,
    ImportDirectoryTableEntrySize = 20,
    ResourceDirectoryTableSize    = 16,
    ResourceDirectoryEntriesSize  = 8,
    ResourceDataEntrySize         = 16
  };
}

struct delay_imports {
  uint32_t attribute;
  uint32_t name;
  uint32_t handle;
  uint32_t iat;
  uint32_t name_table;
  uint32_t bound_iat;
  uint32_t unload_iat;
  uint32_t timestamp;
};

static_assert(sizeof(delay_imports) == 32, "Wrong sizeof(delay_imports)");

#include "structures.inc"

static const HEADER_CHARACTERISTICS header_characteristics_array[] = {
  HEADER_CHARACTERISTICS::IMAGE_FILE_INVALID,
  HEADER_CHARACTERISTICS::IMAGE_FILE_RELOCS_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_EXECUTABLE_IMAGE,
  HEADER_CHARACTERISTICS::IMAGE_FILE_LINE_NUMS_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_LOCAL_SYMS_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_AGGRESSIVE_WS_TRIM,
  HEADER_CHARACTERISTICS::IMAGE_FILE_LARGE_ADDRESS_AWARE,
  HEADER_CHARACTERISTICS::IMAGE_FILE_BYTES_REVERSED_LO,
  HEADER_CHARACTERISTICS::IMAGE_FILE_32BIT_MACHINE,
  HEADER_CHARACTERISTICS::IMAGE_FILE_DEBUG_STRIPPED,
  HEADER_CHARACTERISTICS::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
  HEADER_CHARACTERISTICS::IMAGE_FILE_NET_RUN_FROM_SWAP,
  HEADER_CHARACTERISTICS::IMAGE_FILE_SYSTEM,
  HEADER_CHARACTERISTICS::IMAGE_FILE_DLL,
  HEADER_CHARACTERISTICS::IMAGE_FILE_UP_SYSTEM_ONLY,
  HEADER_CHARACTERISTICS::IMAGE_FILE_BYTES_REVERSED_HI
};


static const SECTION_CHARACTERISTICS section_characteristics_array[] = {
  SECTION_CHARACTERISTICS::IMAGE_SCN_TYPE_NO_PAD,
  SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA,
  SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_UNINITIALIZED_DATA,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_OTHER,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_INFO,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_REMOVE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_COMDAT,
  SECTION_CHARACTERISTICS::IMAGE_SCN_GPREL,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_PURGEABLE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_16BIT,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_LOCKED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_PRELOAD,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_1BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_2BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_4BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_8BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_16BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_32BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_64BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_128BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_256BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_512BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_1024BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_2048BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_4096BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_ALIGN_8192BYTES,
  SECTION_CHARACTERISTICS::IMAGE_SCN_LNK_NRELOC_OVFL,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_DISCARDABLE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_NOT_CACHED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_NOT_PAGED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_SHARED,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ,
  SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE,
};



static const DLL_CHARACTERISTICS dll_characteristics_array[] = {
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NO_SEH,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NO_BIND,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_APPCONTAINER,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_GUARD_CF,
  DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE,
};


static const EXTENDED_WINDOW_STYLES extended_window_styles_array[] = {
  EXTENDED_WINDOW_STYLES::WS_EX_DLGMODALFRAME,
  EXTENDED_WINDOW_STYLES::WS_EX_NOPARENTNOTIFY,
  EXTENDED_WINDOW_STYLES::WS_EX_TOPMOST,
  EXTENDED_WINDOW_STYLES::WS_EX_ACCEPTFILES,
  EXTENDED_WINDOW_STYLES::WS_EX_TRANSPARENT,
  EXTENDED_WINDOW_STYLES::WS_EX_MDICHILD,
  EXTENDED_WINDOW_STYLES::WS_EX_TOOLWINDOW,
  EXTENDED_WINDOW_STYLES::WS_EX_WINDOWEDGE,
  EXTENDED_WINDOW_STYLES::WS_EX_CLIENTEDGE,
  EXTENDED_WINDOW_STYLES::WS_EX_CONTEXTHELP,
  EXTENDED_WINDOW_STYLES::WS_EX_RIGHT,
  EXTENDED_WINDOW_STYLES::WS_EX_LEFT,
  EXTENDED_WINDOW_STYLES::WS_EX_RTLREADING,
  EXTENDED_WINDOW_STYLES::WS_EX_LTRREADING,
  EXTENDED_WINDOW_STYLES::WS_EX_LEFTSCROLLBAR,
  EXTENDED_WINDOW_STYLES::WS_EX_RIGHTSCROLLBAR,
  EXTENDED_WINDOW_STYLES::WS_EX_CONTROLPARENT,
  EXTENDED_WINDOW_STYLES::WS_EX_STATICEDGE,
  EXTENDED_WINDOW_STYLES::WS_EX_APPWINDOW,
};


static const WINDOW_STYLES window_styles_array[] = {
  WINDOW_STYLES::WS_OVERLAPPED,
  WINDOW_STYLES::WS_POPUP,
  WINDOW_STYLES::WS_CHILD,
  WINDOW_STYLES::WS_MINIMIZE,
  WINDOW_STYLES::WS_VISIBLE,
  WINDOW_STYLES::WS_DISABLED,
  WINDOW_STYLES::WS_CLIPSIBLINGS,
  WINDOW_STYLES::WS_CLIPCHILDREN,
  WINDOW_STYLES::WS_MAXIMIZE,
  WINDOW_STYLES::WS_CAPTION,
  WINDOW_STYLES::WS_BORDER,
  WINDOW_STYLES::WS_DLGFRAME,
  WINDOW_STYLES::WS_VSCROLL,
  WINDOW_STYLES::WS_HSCROLL,
  WINDOW_STYLES::WS_SYSMENU,
  WINDOW_STYLES::WS_THICKFRAME,
  WINDOW_STYLES::WS_GROUP,
  WINDOW_STYLES::WS_TABSTOP,
  WINDOW_STYLES::WS_MINIMIZEBOX,
  WINDOW_STYLES::WS_MAXIMIZEBOX,
};


static const DIALOG_BOX_STYLES dialog_box_styles_array[] = {
  DIALOG_BOX_STYLES::DS_ABSALIGN,
  DIALOG_BOX_STYLES::DS_SYSMODAL,
  DIALOG_BOX_STYLES::DS_LOCALEDIT,
  DIALOG_BOX_STYLES::DS_SETFONT,
  DIALOG_BOX_STYLES::DS_MODALFRAME,
  DIALOG_BOX_STYLES::DS_NOIDLEMSG,
  DIALOG_BOX_STYLES::DS_SETFOREGROUND,
  DIALOG_BOX_STYLES::DS_3DLOOK,
  DIALOG_BOX_STYLES::DS_FIXEDSYS,
  DIALOG_BOX_STYLES::DS_NOFAILCREATE,
  DIALOG_BOX_STYLES::DS_CONTROL,
  DIALOG_BOX_STYLES::DS_CENTER,
  DIALOG_BOX_STYLES::DS_CENTERMOUSE,
  DIALOG_BOX_STYLES::DS_CONTEXTHELP,
  DIALOG_BOX_STYLES::DS_SHELLFONT,
};

static const ACCELERATOR_FLAGS accelerator_array[] = {
  ACCELERATOR_FLAGS::FVIRTKEY,
  ACCELERATOR_FLAGS::FNOINVERT,
  ACCELERATOR_FLAGS::FSHIFT,
  ACCELERATOR_FLAGS::FCONTROL,
  ACCELERATOR_FLAGS::FALT,
  ACCELERATOR_FLAGS::END,
};

// From Virtualbox - include/iprt/formats/pecoff.h
template <typename T>
struct load_configuration {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t GlobalFlagsClear;
  uint32_t GlobalFlagsSet;
  uint32_t CriticalSectionDefaultTimeout;
  T        DeCommitFreeBlockThreshold;
  T        DeCommitTotalFreeThreshold;
  T        LockPrefixTable;
  T        MaximumAllocationSize;
  T        VirtualMemoryThreshold;
  T        ProcessAffinityMask;
  uint32_t ProcessHeapFlags;
  uint16_t CSDVersion;
  uint16_t Reserved1;
  T        EditList;
  T        SecurityCookie;
};

template <typename T>
struct load_configuration_v0 : load_configuration<T> {
  T SEHandlerTable;
  T SEHandlerCount;
};


#pragma pack(4)
// Windows 10 - 9879

template <typename T>
struct load_configuration_v1 : load_configuration_v0<T> {
  T        GuardCFCheckFunctionPointer;
  T        GuardCFDispatchFunctionPointer;
  T        GuardCFFunctionTable;
  T        GuardCFFunctionCount;
  uint32_t GuardFlags;
};
#pragma pack()


// Windows 10 - 9879
template <typename T>
struct load_configuration_v2 : load_configuration_v1<T> {
  pe_code_integrity CodeIntegrity;
};


template <typename T>
struct load_configuration_v3 : load_configuration_v2<T> {
  T GuardAddressTakenIatEntryTable;
  T GuardAddressTakenIatEntryCount;
  T GuardLongJumpTargetTable;
  T GuardLongJumpTargetCount;
};


template <typename T>
struct load_configuration_v4 : load_configuration_v3<T> {
  T DynamicValueRelocTable;
  T HybridMetadataPointer;
};


template <typename T>
struct load_configuration_v5 : load_configuration_v4<T> {
  T        GuardRFFailureRoutine;
  T        GuardRFFailureRoutineFunctionPointer;
  uint32_t DynamicValueRelocTableOffset;
  uint16_t DynamicValueRelocTableSection;
  uint16_t Reserved2;
};


#pragma pack(4)
template <typename T>
struct load_configuration_v6 : load_configuration_v5<T> {
  T        GuardRFVerifyStackPointerFunctionPointer;
  uint32_t HotPatchTableOffset;
};
#pragma pack()

template <typename T>
struct load_configuration_v7 : load_configuration_v6<T> {
  uint32_t Reserved3;
  T        AddressOfSomeUnicodeString;
};

class PE32 {
  public:
    using pe_optional_header = pe32_optional_header;
    using pe_tls             = pe32_tls;
    using uint               = uint32_t;

    using load_configuration_t    = load_configuration<uint32_t>;
    using load_configuration_v0_t = load_configuration_v0<uint32_t>;
    using load_configuration_v1_t = load_configuration_v1<uint32_t>;
    using load_configuration_v2_t = load_configuration_v2<uint32_t>;
    using load_configuration_v3_t = load_configuration_v3<uint32_t>;
    using load_configuration_v4_t = load_configuration_v4<uint32_t>;
    using load_configuration_v5_t = load_configuration_v5<uint32_t>;
    using load_configuration_v6_t = load_configuration_v6<uint32_t>;
    using load_configuration_v7_t = load_configuration_v7<uint32_t>;


    static_assert(sizeof(load_configuration_t)    == 0x40, "");
    static_assert(sizeof(load_configuration_v0_t) == 0x48, "");
    static_assert(sizeof(load_configuration_v1_t) == 0x5c, "");
    static_assert(sizeof(load_configuration_v2_t) == 0x68, "");
    static_assert(sizeof(load_configuration_v3_t) == 0x78, "");
    static_assert(sizeof(load_configuration_v4_t) == 0x80, "");
    static_assert(sizeof(load_configuration_v5_t) == 0x90, "");
    static_assert(sizeof(load_configuration_v6_t) == 0x98, "");
    //static_assert(sizeof(LoadConfiguration_V7) == 0xA0, "");

    static const std::map<WIN_VERSION, size_t> load_configuration_sizes;
 };


class PE64 {
  public:
    using pe_optional_header = pe64_optional_header;
    using pe_tls             = pe64_tls;
    using uint               = uint64_t;

    using load_configuration_t    = load_configuration<uint64_t>;
    using load_configuration_v0_t = load_configuration_v0<uint64_t>;
    using load_configuration_v1_t = load_configuration_v1<uint64_t>;
    using load_configuration_v2_t = load_configuration_v2<uint64_t>;
    using load_configuration_v3_t = load_configuration_v3<uint64_t>;
    using load_configuration_v4_t = load_configuration_v4<uint64_t>;
    using load_configuration_v5_t = load_configuration_v5<uint64_t>;
    using load_configuration_v6_t = load_configuration_v6<uint64_t>;
    using load_configuration_v7_t = load_configuration_v7<uint64_t>;

    static_assert(sizeof(load_configuration_t)    == 0x60,  "");
    static_assert(sizeof(load_configuration_v0_t) == 0x70,  "");
    static_assert(sizeof(load_configuration_v1_t) == 0x94,  "");
    static_assert(sizeof(load_configuration_v2_t) == 0xA0,  "");
    static_assert(sizeof(load_configuration_v3_t) == 0xC0,  "");
    static_assert(sizeof(load_configuration_v4_t) == 0xD0,  "");
    static_assert(sizeof(load_configuration_v5_t) == 0xE8,  "");
    static_assert(sizeof(load_configuration_v6_t) == 0xF4,  "");
    static_assert(sizeof(load_configuration_v7_t) == 0x100, "");

    static const std::map<WIN_VERSION, size_t> load_configuration_sizes;
};
}


} // end namesapce ELF
}

#endif
