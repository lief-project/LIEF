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
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"
#include "LIEF/PE/enums.hpp"

#include "frozen.hpp"

namespace LIEF {
namespace PE {

const char* to_string(PE_TYPE e) {
  CONST_MAP(PE_TYPE, const char*, 2) enumStrings {
    { PE_TYPE::PE32,     "PE32" },
    { PE_TYPE::PE32_PLUS,"PE32_PLUS" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(PE_SECTION_TYPES e) {
  CONST_MAP(PE_SECTION_TYPES, const char*, 10) enumStrings {
    { PE_SECTION_TYPES::TEXT,       "TEXT"       },
    { PE_SECTION_TYPES::TLS,        "TLS_"       },
    { PE_SECTION_TYPES::IMPORT,     "IDATA"      },
    { PE_SECTION_TYPES::DATA,       "DATA"       },
    { PE_SECTION_TYPES::BSS,        "BSS"        },
    { PE_SECTION_TYPES::RESOURCE,   "RESOURCE"   },
    { PE_SECTION_TYPES::RELOCATION, "RELOCATION" },
    { PE_SECTION_TYPES::EXPORT,     "EXPORT"     },
    { PE_SECTION_TYPES::DEBUG_TYPE, "DEBUG"      },
    { PE_SECTION_TYPES::UNKNOWN,    "UNKNOWN"    },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(SYMBOL_BASE_TYPES e) {
  CONST_MAP(SYMBOL_BASE_TYPES, const char*, 16) enumStrings {
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_NULL,   "NULL"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_VOID,   "VOID"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_CHAR,   "CHAR"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_SHORT,  "SHORT"  },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_INT,    "INT"    },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_LONG,   "LONG"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_FLOAT,  "FLOAT"  },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_DOUBLE, "DOUBLE" },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_STRUCT, "STRUCT" },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_UNION,  "UNION"  },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_ENUM,   "ENUM"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_MOE,    "MOE"    },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_BYTE,   "BYTE"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_WORD,   "WORD"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_UINT,   "UINT"   },
    { SYMBOL_BASE_TYPES::IMAGE_SYM_TYPE_DWORD,  "DWORD"  },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(SYMBOL_COMPLEX_TYPES e) {
  CONST_MAP(SYMBOL_COMPLEX_TYPES, const char*, 5) enumStrings {
    { SYMBOL_COMPLEX_TYPES::IMAGE_SYM_DTYPE_NULL,     "NULL"               },
    { SYMBOL_COMPLEX_TYPES::IMAGE_SYM_DTYPE_POINTER,  "POINTER"            },
    { SYMBOL_COMPLEX_TYPES::IMAGE_SYM_DTYPE_FUNCTION, "FUNCTION"           },
    { SYMBOL_COMPLEX_TYPES::IMAGE_SYM_DTYPE_ARRAY,    "ARRAY"              },
    { SYMBOL_COMPLEX_TYPES::SCT_COMPLEX_TYPE_SHIFT,   "COMPLEX_TYPE_SHIFT" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(SYMBOL_SECTION_NUMBER e) {
  CONST_MAP(SYMBOL_SECTION_NUMBER, const char*, 3) enumStrings {
    { SYMBOL_SECTION_NUMBER::IMAGE_SYM_DEBUG,     "DEBUG"     },
    { SYMBOL_SECTION_NUMBER::IMAGE_SYM_ABSOLUTE,  "ABSOLUTE"  },
    { SYMBOL_SECTION_NUMBER::IMAGE_SYM_UNDEFINED, "UNDEFINED" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(SYMBOL_STORAGE_CLASS e) {
  CONST_MAP(SYMBOL_STORAGE_CLASS, const char*, 24) enumStrings {
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_END_OF_FUNCTION,  "END_OF_FUNCTION"  },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_NULL,             "NULL"             },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_AUTOMATIC,        "AUTOMATIC"        },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL,         "EXTERNAL"         },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_STATIC,           "STATIC"           },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_REGISTER,         "REGISTER"         },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL_DEF,     "EXTERNAL_DEF"     },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_LABEL,            "LABEL"            },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_UNDEFINED_LABEL,  "UNDEFINED_LABEL"  },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_MEMBER_OF_STRUCT, "MEMBER_OF_STRUCT" },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_UNION_TAG,        "UNION_TAG"        },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_TYPE_DEFINITION,  "TYPE_DEFINITION"  },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_UNDEFINED_STATIC, "UDEFINED_STATIC"  },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_ENUM_TAG,         "ENUM_TAG"         },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_MEMBER_OF_ENUM,   "MEMBER_OF_ENUM"   },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_REGISTER_PARAM,   "REGISTER_PARAM"   },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_BIT_FIELD,        "BIT_FIELD"        },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_BLOCK,            "BLOCK"            },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_FUNCTION,         "FUNCTION"         },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_END_OF_STRUCT,    "END_OF_STRUCT"    },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_FILE,             "FILE"             },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_SECTION,          "SECTION"          },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_WEAK_EXTERNAL,    "WEAK_EXTERNAL"    },
    { SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_CLR_TOKEN,        "CLR_TOKEN"        },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(RELOCATIONS_I386 e) {
  CONST_MAP(RELOCATIONS_I386, const char*, 11) enumStrings {
    { RELOCATIONS_I386::IMAGE_REL_I386_ABSOLUTE,  "ABSOLUTE" },
    { RELOCATIONS_I386::IMAGE_REL_I386_DIR16,     "DIR16"    },
    { RELOCATIONS_I386::IMAGE_REL_I386_REL16,     "REL16"    },
    { RELOCATIONS_I386::IMAGE_REL_I386_DIR32,     "DIR32"    },
    { RELOCATIONS_I386::IMAGE_REL_I386_DIR32NB,   "DIR32NB"  },
    { RELOCATIONS_I386::IMAGE_REL_I386_SEG12,     "SEG12"    },
    { RELOCATIONS_I386::IMAGE_REL_I386_SECTION,   "SECTION"  },
    { RELOCATIONS_I386::IMAGE_REL_I386_SECREL,    "SECREL"   },
    { RELOCATIONS_I386::IMAGE_REL_I386_TOKEN,     "TOKEN"    },
    { RELOCATIONS_I386::IMAGE_REL_I386_SECREL7,   "SECREL7"  },
    { RELOCATIONS_I386::IMAGE_REL_I386_REL32,     "REL32"    },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}



const char* to_string(RELOCATIONS_AMD64 e) {
  CONST_MAP(RELOCATIONS_AMD64, const char*, 17) enumStrings {
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_ABSOLUTE, "ABSOLUTE" },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_ADDR64,   "ADDR64"   },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_ADDR32,   "ADDR32"   },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_ADDR32NB, "ADDR32NB" },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_REL32,    "REL32"    },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_REL32_1,  "REL32_1"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_REL32_2,  "REL32_2"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_REL32_3,  "REL32_3"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_REL32_4,  "REL32_4"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_REL32_5,  "REL32_5"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_SECTION,  "SECTION"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_SECREL,   "SECREL"   },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_SECREL7,  "SECREL7"  },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_TOKEN,    "TOKEN"    },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_SREL32,   "SREL32"   },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_PAIR,     "PAIR"     },
    { RELOCATIONS_AMD64::IMAGE_REL_AMD64_SSPAN32,  "SSPAN32"  },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}



const char* to_string(RELOCATIONS_ARM e) {
  CONST_MAP(RELOCATIONS_ARM, const char*, 15) enumStrings {
    { RELOCATIONS_ARM::IMAGE_REL_ARM_ABSOLUTE,  "ABSOLUTE"  },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_ADDR32,    "ADDR32"    },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_ADDR32NB,  "ADDR32NB"  },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BRANCH24,  "BRANCH24"  },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BRANCH11,  "BRANCH11"  },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_TOKEN,     "TOKEN"     },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BLX24,     "BLX24"     },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BLX11,     "BLX11"     },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_SECTION,   "SECTION"   },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_SECREL,    "SECREL"    },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_MOV32A,    "MOV32A"    },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_MOV32T,    "MOV32T"    },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BRANCH20T, "BRANCH20T" },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BRANCH24T, "BRANCH24T" },
    { RELOCATIONS_ARM::IMAGE_REL_ARM_BLX23T,    "BLX23T"    },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(EXTENDED_WINDOW_STYLES e) {
  CONST_MAP(EXTENDED_WINDOW_STYLES, const char*, 17) enumStrings {
    { EXTENDED_WINDOW_STYLES::WS_EX_DLGMODALFRAME,  "DLGMODALFRAME"  },
    { EXTENDED_WINDOW_STYLES::WS_EX_NOPARENTNOTIFY, "NOPARENTNOTIFY" },
    { EXTENDED_WINDOW_STYLES::WS_EX_TOPMOST,        "TOPMOST"        },
    { EXTENDED_WINDOW_STYLES::WS_EX_ACCEPTFILES,    "ACCEPTFILES"    },
    { EXTENDED_WINDOW_STYLES::WS_EX_TRANSPARENT,    "TRANSPARENT"    },
    { EXTENDED_WINDOW_STYLES::WS_EX_MDICHILD,       "MDICHILD"       },
    { EXTENDED_WINDOW_STYLES::WS_EX_TOOLWINDOW,     "TOOLWINDOW"     },
    { EXTENDED_WINDOW_STYLES::WS_EX_WINDOWEDGE,     "WINDOWEDGE"     },
    { EXTENDED_WINDOW_STYLES::WS_EX_CLIENTEDGE,     "CLIENTEDGE"     },
    { EXTENDED_WINDOW_STYLES::WS_EX_CONTEXTHELP,    "CONTEXTHELP"    },
    { EXTENDED_WINDOW_STYLES::WS_EX_RIGHT,          "RIGHT"          },
    { EXTENDED_WINDOW_STYLES::WS_EX_LEFT,           "LEFT"           },
    { EXTENDED_WINDOW_STYLES::WS_EX_RTLREADING,     "RTLREADING"     },
    { EXTENDED_WINDOW_STYLES::WS_EX_LEFTSCROLLBAR,  "LEFTSCROLLBAR"  },
    { EXTENDED_WINDOW_STYLES::WS_EX_CONTROLPARENT,  "CONTROLPARENT"  },
    { EXTENDED_WINDOW_STYLES::WS_EX_STATICEDGE,     "STATICEDGE"     },
    { EXTENDED_WINDOW_STYLES::WS_EX_APPWINDOW,      "APPWINDOW"      },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(WINDOW_STYLES e) {
  CONST_MAP(WINDOW_STYLES, const char*, 18) enumStrings {
    { WINDOW_STYLES::WS_OVERLAPPED,   "OVERLAPPED"   },
    { WINDOW_STYLES::WS_POPUP,        "POPUP"        },
    { WINDOW_STYLES::WS_CHILD,        "CHILD"        },
    { WINDOW_STYLES::WS_MINIMIZE,     "MINIMIZE"     },
    { WINDOW_STYLES::WS_VISIBLE,      "VISIBLE"      },
    { WINDOW_STYLES::WS_DISABLED,     "DISABLED"     },
    { WINDOW_STYLES::WS_CLIPSIBLINGS, "CLIPSIBLINGS" },
    { WINDOW_STYLES::WS_CLIPCHILDREN, "CLIPCHILDREN" },
    { WINDOW_STYLES::WS_MAXIMIZE,     "MAXIMIZE"     },
    { WINDOW_STYLES::WS_CAPTION,      "CAPTION"      },
    { WINDOW_STYLES::WS_BORDER,       "BORDER"       },
    { WINDOW_STYLES::WS_DLGFRAME,     "DLGFRAME"     },
    { WINDOW_STYLES::WS_VSCROLL,      "VSCROLL"      },
    { WINDOW_STYLES::WS_HSCROLL,      "HSCROLL"      },
    { WINDOW_STYLES::WS_SYSMENU,      "SYSMENU"      },
    { WINDOW_STYLES::WS_THICKFRAME,   "THICKFRAME"   },
    { WINDOW_STYLES::WS_MINIMIZEBOX,  "MINIMIZEBOX"  },
    { WINDOW_STYLES::WS_MAXIMIZEBOX,  "MAXIMIZEBOX"  },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(DIALOG_BOX_STYLES e) {
  CONST_MAP(DIALOG_BOX_STYLES, const char*, 15) enumStrings {
    { DIALOG_BOX_STYLES::DS_ABSALIGN,      "ABSALIGN"      },
    { DIALOG_BOX_STYLES::DS_SYSMODAL,      "SYSMODAL"      },
    { DIALOG_BOX_STYLES::DS_LOCALEDIT,     "LOCALEDIT"     },
    { DIALOG_BOX_STYLES::DS_SETFONT,       "SETFONT"       },
    { DIALOG_BOX_STYLES::DS_MODALFRAME,    "MODALFRAME"    },
    { DIALOG_BOX_STYLES::DS_NOIDLEMSG,     "NOIDLEMSG"     },
    { DIALOG_BOX_STYLES::DS_SETFOREGROUND, "SETFOREGROUND" },
    { DIALOG_BOX_STYLES::DS_3DLOOK,        "D3DLOOK"       },
    { DIALOG_BOX_STYLES::DS_FIXEDSYS,      "FIXEDSYS"      },
    { DIALOG_BOX_STYLES::DS_NOFAILCREATE,  "NOFAILCREATE"  },
    { DIALOG_BOX_STYLES::DS_CONTROL,       "CONTROL"       },
    { DIALOG_BOX_STYLES::DS_CENTER,        "CENTER"        },
    { DIALOG_BOX_STYLES::DS_CENTERMOUSE,   "CENTERMOUSE"   },
    { DIALOG_BOX_STYLES::DS_CONTEXTHELP,   "CONTEXTHELP"   },
    { DIALOG_BOX_STYLES::DS_SHELLFONT,     "SHELLFONT"     },
  };

  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(FIXED_VERSION_OS e) {
  CONST_MAP(FIXED_VERSION_OS, const char*, 14) enumStrings {
    { FIXED_VERSION_OS::VOS_UNKNOWN,       "UNKNOWN"       },
    { FIXED_VERSION_OS::VOS_DOS,           "DOS"           },
    { FIXED_VERSION_OS::VOS_NT,            "NT"            },
    { FIXED_VERSION_OS::VOS__WINDOWS16,    "WINDOWS16"     },
    { FIXED_VERSION_OS::VOS__WINDOWS32,    "WINDOWS32"     },
    { FIXED_VERSION_OS::VOS_OS216,         "OS216"         },
    { FIXED_VERSION_OS::VOS_OS232,         "OS232"         },
    { FIXED_VERSION_OS::VOS__PM16,         "PM16"          },
    { FIXED_VERSION_OS::VOS__PM32,         "PM32"          },
    { FIXED_VERSION_OS::VOS_DOS_WINDOWS16, "DOS_WINDOWS16" },
    { FIXED_VERSION_OS::VOS_DOS_WINDOWS32, "DOS_WINDOWS32" },
    { FIXED_VERSION_OS::VOS_NT_WINDOWS32,  "NT_WINDOWS32"  },
    { FIXED_VERSION_OS::VOS_OS216_PM16,    "OS216_PM16"    },
    { FIXED_VERSION_OS::VOS_OS232_PM32,    "OS232_PM32"    },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(FIXED_VERSION_FILE_FLAGS e) {
  CONST_MAP(FIXED_VERSION_FILE_FLAGS, const char*, 6) enumStrings {
    { FIXED_VERSION_FILE_FLAGS::VS_FF_DEBUG,        "DEBUG"        },
    { FIXED_VERSION_FILE_FLAGS::VS_FF_INFOINFERRED, "INFOINFERRED" },
    { FIXED_VERSION_FILE_FLAGS::VS_FF_PATCHED,      "PATCHED"      },
    { FIXED_VERSION_FILE_FLAGS::VS_FF_PRERELEASE,   "PRERELEASE"   },
    { FIXED_VERSION_FILE_FLAGS::VS_FF_PRIVATEBUILD, "PRIVATEBUILD" },
    { FIXED_VERSION_FILE_FLAGS::VS_FF_SPECIALBUILD, "SPECIALBUILD" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(FIXED_VERSION_FILE_TYPES e) {
  CONST_MAP(FIXED_VERSION_FILE_TYPES, const char*, 7) enumStrings {
    { FIXED_VERSION_FILE_TYPES::VFT_APP,        "APP"        },
    { FIXED_VERSION_FILE_TYPES::VFT_DLL,        "DLL"        },
    { FIXED_VERSION_FILE_TYPES::VFT_DRV,        "DRV"        },
    { FIXED_VERSION_FILE_TYPES::VFT_FONT,       "FONT"       },
    { FIXED_VERSION_FILE_TYPES::VFT_STATIC_LIB, "STATIC_LIB" },
    { FIXED_VERSION_FILE_TYPES::VFT_UNKNOWN,    "UNKNOWN"    },
    { FIXED_VERSION_FILE_TYPES::VFT_VXD,        "VXD"        },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}


const char* to_string(FIXED_VERSION_FILE_SUB_TYPES e) {
  CONST_MAP(FIXED_VERSION_FILE_SUB_TYPES, const char*, 12) enumStrings {
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_COMM,              "DRV_COMM"              },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_DISPLAY,           "DRV_DISPLAY"           },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_INSTALLABLE,       "DRV_INSTALLABLE"       },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_KEYBOARD,          "DRV_KEYBOARD"          },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_LANGUAGE,          "DRV_LANGUAGE"          },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_MOUSE,             "DRV_MOUSE"             },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_NETWORK,           "DRV_NETWORK"           },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_PRINTER,           "DRV_PRINTER"           },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_SOUND,             "DRV_SOUND"             },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_SYSTEM,            "DRV_SYSTEM"            },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_DRV_VERSIONED_PRINTER, "DRV_VERSIONED_PRINTER" },
    { FIXED_VERSION_FILE_SUB_TYPES::VFT2_UNKNOWN,               "UNKNOWN"               },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(CODE_PAGES e) {
  CONST_MAP(CODE_PAGES, const char*, 140) enumStrings {
    { CODE_PAGES::CP_IBM037,                  "IBM037"},
    { CODE_PAGES::CP_IBM437,                  "IBM437"},
    { CODE_PAGES::CP_IBM500,                  "IBM500"},
    { CODE_PAGES::CP_ASMO_708,                "ASMO_708"},
    { CODE_PAGES::CP_DOS_720,                 "DOS_720"},
    { CODE_PAGES::CP_IBM737,                  "IBM737"},
    { CODE_PAGES::CP_IBM775,                  "IBM775"},
    { CODE_PAGES::CP_IBM850,                  "IBM850"},
    { CODE_PAGES::CP_IBM852,                  "IBM852"},
    { CODE_PAGES::CP_IBM855,                  "IBM855"},
    { CODE_PAGES::CP_IBM857,                  "IBM857"},
    { CODE_PAGES::CP_IBM00858,                "IBM00858"},
    { CODE_PAGES::CP_IBM860,                  "IBM860"},
    { CODE_PAGES::CP_IBM861,                  "IBM861"},
    { CODE_PAGES::CP_DOS_862,                 "DOS_862"},
    { CODE_PAGES::CP_IBM863,                  "IBM863"},
    { CODE_PAGES::CP_IBM864,                  "IBM864"},
    { CODE_PAGES::CP_IBM865,                  "IBM865"},
    { CODE_PAGES::CP_CP866,                   "CP866"},
    { CODE_PAGES::CP_IBM869,                  "IBM869"},
    { CODE_PAGES::CP_IBM870,                  "IBM870"},
    { CODE_PAGES::CP_WINDOWS_874,             "WINDOWS_874"},
    { CODE_PAGES::CP_CP875,                   "CP875"},
    { CODE_PAGES::CP_SHIFT_JIS,               "SHIFT_JIS"},
    { CODE_PAGES::CP_GB2312,                  "GB2312"},
    { CODE_PAGES::CP_KS_C_5601_1987,          "KS_C_5601_1987"},
    { CODE_PAGES::CP_BIG5,                    "BIG5"},
    { CODE_PAGES::CP_IBM1026,                 "IBM1026"},
    { CODE_PAGES::CP_IBM01047,                "IBM01047"},
    { CODE_PAGES::CP_IBM01140,                "IBM01140"},
    { CODE_PAGES::CP_IBM01141,                "IBM01141"},
    { CODE_PAGES::CP_IBM01142,                "IBM01142"},
    { CODE_PAGES::CP_IBM01143,                "IBM01143"},
    { CODE_PAGES::CP_IBM01144,                "IBM01144"},
    { CODE_PAGES::CP_IBM01145,                "IBM01145"},
    { CODE_PAGES::CP_IBM01146,                "IBM01146"},
    { CODE_PAGES::CP_IBM01147,                "IBM01147"},
    { CODE_PAGES::CP_IBM01148,                "IBM01148"},
    { CODE_PAGES::CP_IBM01149,                "IBM01149"},
    { CODE_PAGES::CP_UTF_16,                  "UTF_16"},
    { CODE_PAGES::CP_UNICODEFFFE,             "UNICODEFFFE"},
    { CODE_PAGES::CP_WINDOWS_1250,            "WINDOWS_1250"},
    { CODE_PAGES::CP_WINDOWS_1251,            "WINDOWS_1251"},
    { CODE_PAGES::CP_WINDOWS_1252,            "WINDOWS_1252"},
    { CODE_PAGES::CP_WINDOWS_1253,            "WINDOWS_1253"},
    { CODE_PAGES::CP_WINDOWS_1254,            "WINDOWS_1254"},
    { CODE_PAGES::CP_WINDOWS_1255,            "WINDOWS_1255"},
    { CODE_PAGES::CP_WINDOWS_1256,            "WINDOWS_1256"},
    { CODE_PAGES::CP_WINDOWS_1257,            "WINDOWS_1257"},
    { CODE_PAGES::CP_WINDOWS_1258,            "WINDOWS_1258"},
    { CODE_PAGES::CP_JOHAB,                   "JOHAB"},
    { CODE_PAGES::CP_MACINTOSH,               "MACINTOSH"},
    { CODE_PAGES::CP_X_MAC_JAPANESE,          "X_MAC_JAPANESE"},
    { CODE_PAGES::CP_X_MAC_CHINESETRAD,       "X_MAC_CHINESETRAD"},
    { CODE_PAGES::CP_X_MAC_KOREAN,            "X_MAC_KOREAN"},
    { CODE_PAGES::CP_X_MAC_ARABIC,            "X_MAC_ARABIC"},
    { CODE_PAGES::CP_X_MAC_HEBREW,            "X_MAC_HEBREW"},
    { CODE_PAGES::CP_X_MAC_GREEK,             "X_MAC_GREEK"},
    { CODE_PAGES::CP_X_MAC_CYRILLIC,          "X_MAC_CYRILLIC"},
    { CODE_PAGES::CP_X_MAC_CHINESESIMP,       "X_MAC_CHINESESIMP"},
    { CODE_PAGES::CP_X_MAC_ROMANIAN,          "X_MAC_ROMANIAN"},
    { CODE_PAGES::CP_X_MAC_UKRAINIAN,         "X_MAC_UKRAINIAN"},
    { CODE_PAGES::CP_X_MAC_THAI,              "X_MAC_THAI"},
    { CODE_PAGES::CP_X_MAC_CE,                "X_MAC_CE"},
    { CODE_PAGES::CP_X_MAC_ICELANDIC,         "X_MAC_ICELANDIC"},
    { CODE_PAGES::CP_X_MAC_TURKISH,           "X_MAC_TURKISH"},
    { CODE_PAGES::CP_X_MAC_CROATIAN,          "X_MAC_CROATIAN"},
    { CODE_PAGES::CP_UTF_32,                  "UTF_32"},
    { CODE_PAGES::CP_UTF_32BE,                "UTF_32BE"},
    { CODE_PAGES::CP_X_CHINESE_CNS,           "X_CHINESE_CNS"},
    { CODE_PAGES::CP_X_CP20001,               "X_CP20001"},
    { CODE_PAGES::CP_X_CHINESE_ETEN,          "X_CHINESE_ETEN"},
    { CODE_PAGES::CP_X_CP20003,               "X_CP20003"},
    { CODE_PAGES::CP_X_CP20004,               "X_CP20004"},
    { CODE_PAGES::CP_X_CP20005,               "X_CP20005"},
    { CODE_PAGES::CP_X_IA5,                   "X_IA5"},
    { CODE_PAGES::CP_X_IA5_GERMAN,            "X_IA5_GERMAN"},
    { CODE_PAGES::CP_X_IA5_SWEDISH,           "X_IA5_SWEDISH"},
    { CODE_PAGES::CP_X_IA5_NORWEGIAN,         "X_IA5_NORWEGIAN"},
    { CODE_PAGES::CP_US_ASCII,                "US_ASCII"},
    { CODE_PAGES::CP_X_CP20261,               "X_CP20261"},
    { CODE_PAGES::CP_X_CP20269,               "X_CP20269"},
    { CODE_PAGES::CP_IBM273,                  "IBM273"},
    { CODE_PAGES::CP_IBM277,                  "IBM277"},
    { CODE_PAGES::CP_IBM278,                  "IBM278"},
    { CODE_PAGES::CP_IBM280,                  "IBM280"},
    { CODE_PAGES::CP_IBM284,                  "IBM284"},
    { CODE_PAGES::CP_IBM285,                  "IBM285"},
    { CODE_PAGES::CP_IBM290,                  "IBM290"},
    { CODE_PAGES::CP_IBM297,                  "IBM297"},
    { CODE_PAGES::CP_IBM420,                  "IBM420"},
    { CODE_PAGES::CP_IBM423,                  "IBM423"},
    { CODE_PAGES::CP_IBM424,                  "IBM424"},
    { CODE_PAGES::CP_X_EBCDIC_KOREANEXTENDED, "X_EBCDIC_KOREANEXTENDED"},
    { CODE_PAGES::CP_IBM_THAI,                "IBM_THAI"},
    { CODE_PAGES::CP_KOI8_R,                  "KOI8_R"},
    { CODE_PAGES::CP_IBM871,                  "IBM871"},
    { CODE_PAGES::CP_IBM880,                  "IBM880"},
    { CODE_PAGES::CP_IBM905,                  "IBM905"},
    { CODE_PAGES::CP_IBM00924,                "IBM00924"},
    { CODE_PAGES::CP_EUC_JP_JIS,              "EUC_JP_JIS"},
    { CODE_PAGES::CP_X_CP20936,               "X_CP20936"},
    { CODE_PAGES::CP_X_CP20949,               "X_CP20949"},
    { CODE_PAGES::CP_CP1025,                  "CP1025"},
    { CODE_PAGES::CP_KOI8_U,                  "KOI8_U"},
    { CODE_PAGES::CP_ISO_8859_1,              "ISO_8859_1"},
    { CODE_PAGES::CP_ISO_8859_2,              "ISO_8859_2"},
    { CODE_PAGES::CP_ISO_8859_3,              "ISO_8859_3"},
    { CODE_PAGES::CP_ISO_8859_4,              "ISO_8859_4"},
    { CODE_PAGES::CP_ISO_8859_5,              "ISO_8859_5"},
    { CODE_PAGES::CP_ISO_8859_6,              "ISO_8859_6"},
    { CODE_PAGES::CP_ISO_8859_7,              "ISO_8859_7"},
    { CODE_PAGES::CP_ISO_8859_8,              "ISO_8859_8"},
    { CODE_PAGES::CP_ISO_8859_9,              "ISO_8859_9"},
    { CODE_PAGES::CP_ISO_8859_13,             "ISO_8859_13"},
    { CODE_PAGES::CP_ISO_8859_15,             "ISO_8859_15"},
    { CODE_PAGES::CP_X_EUROPA,                "X_EUROPA"},
    { CODE_PAGES::CP_ISO_8859_8_I,            "ISO_8859_8_I"},
    { CODE_PAGES::CP_ISO_2022_JP,             "ISO_2022_JP"},
    { CODE_PAGES::CP_CSISO2022JP,             "CSISO2022JP"},
    { CODE_PAGES::CP_ISO_2022_JP_JIS,         "ISO_2022_JP_JIS"},
    { CODE_PAGES::CP_ISO_2022_KR,             "ISO_2022_KR"},
    { CODE_PAGES::CP_X_CP50227,               "X_CP50227"},
    { CODE_PAGES::CP_EUC_JP,                  "EUC_JP"},
    { CODE_PAGES::CP_EUC_CN,                  "EUC_CN"},
    { CODE_PAGES::CP_EUC_KR,                  "EUC_KR"},
    { CODE_PAGES::CP_HZ_GB_2312,              "HZ_GB_2312"},
    { CODE_PAGES::CP_GB18030,                 "GB18030"},
    { CODE_PAGES::CP_X_ISCII_DE,              "X_ISCII_DE"},
    { CODE_PAGES::CP_X_ISCII_BE,              "X_ISCII_BE"},
    { CODE_PAGES::CP_X_ISCII_TA,              "X_ISCII_TA"},
    { CODE_PAGES::CP_X_ISCII_TE,              "X_ISCII_TE"},
    { CODE_PAGES::CP_X_ISCII_AS,              "X_ISCII_AS"},
    { CODE_PAGES::CP_X_ISCII_OR,              "X_ISCII_OR"},
    { CODE_PAGES::CP_X_ISCII_KA,              "X_ISCII_KA"},
    { CODE_PAGES::CP_X_ISCII_MA,              "X_ISCII_MA"},
    { CODE_PAGES::CP_X_ISCII_GU,              "X_ISCII_GU"},
    { CODE_PAGES::CP_X_ISCII_PA,              "X_ISCII_PA"},
    { CODE_PAGES::CP_UTF_7,                   "UTF_7"},
    { CODE_PAGES::CP_UTF_8,                   "UTF_8"},
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}



const char* to_string(ACCELERATOR_FLAGS e) {
  CONST_MAP(ACCELERATOR_FLAGS, const char*, 6) enumStrings {
    { ACCELERATOR_FLAGS::FVIRTKEY,  "FVIRTKEY"  },
    { ACCELERATOR_FLAGS::FNOINVERT, "FNOINVERT" },
    { ACCELERATOR_FLAGS::FSHIFT,    "FSHIFT"    },
    { ACCELERATOR_FLAGS::FCONTROL,  "FCONTROL"  },
    { ACCELERATOR_FLAGS::FALT,      "FALT"      },
    { ACCELERATOR_FLAGS::END,       "END"       },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "Out of range" : it->second;
}

const char* to_string(ACCELERATOR_VK_CODES e) {
  CONST_MAP(ACCELERATOR_VK_CODES, const char*, 174) enumStrings {
    { ACCELERATOR_VK_CODES::VK_LBUTTON,             "VK_LBUTTON"             },
    { ACCELERATOR_VK_CODES::VK_RBUTTON,             "VK_RBUTTON"             },
    { ACCELERATOR_VK_CODES::VK_CANCEL,              "VK_CANCEL"              },
    { ACCELERATOR_VK_CODES::VK_MBUTTON,             "VK_MBUTTON"             },
    { ACCELERATOR_VK_CODES::VK_XBUTTON1,            "VK_XBUTTON1"            },
    { ACCELERATOR_VK_CODES::VK_XBUTTON2,            "VK_XBUTTON2"            },
    { ACCELERATOR_VK_CODES::VK_BACK,                "VK_BACK"                },
    { ACCELERATOR_VK_CODES::VK_TAB,                 "VK_TAB"                 },
    { ACCELERATOR_VK_CODES::VK_CLEAR,               "VK_CLEAR"               },
    { ACCELERATOR_VK_CODES::VK_RETURN,              "VK_RETURN"              },
    { ACCELERATOR_VK_CODES::VK_SHIFT,               "VK_SHIFT"               },
    { ACCELERATOR_VK_CODES::VK_CONTROL,             "VK_CONTROL"             },
    { ACCELERATOR_VK_CODES::VK_MENU,                "VK_MENU"                },
    { ACCELERATOR_VK_CODES::VK_PAUSE,               "VK_PAUSE"               },
    { ACCELERATOR_VK_CODES::VK_CAPITAL,             "VK_CAPITAL"             },
    { ACCELERATOR_VK_CODES::VK_KANA,                "VK_KANA"                },
    { ACCELERATOR_VK_CODES::VK_HANGUEL,             "VK_HANGUEL"             },
    { ACCELERATOR_VK_CODES::VK_HANGUL,              "VK_HANGUL"              },
    { ACCELERATOR_VK_CODES::VK_IME_ON,              "VK_IME_ON"              },
    { ACCELERATOR_VK_CODES::VK_JUNJA,               "VK_JUNJA"               },
    { ACCELERATOR_VK_CODES::VK_FINAL,               "VK_FINAL"               },
    { ACCELERATOR_VK_CODES::VK_HANJA,               "VK_HANJA"               },
    { ACCELERATOR_VK_CODES::VK_KANJI,               "VK_KANJI"               },
    { ACCELERATOR_VK_CODES::VK_IME_OFF,             "VK_IME_OFF"             },
    { ACCELERATOR_VK_CODES::VK_ESCAPE,              "VK_ESCAPE"              },
    { ACCELERATOR_VK_CODES::VK_CONVERT,             "VK_CONVERT"             },
    { ACCELERATOR_VK_CODES::VK_NONCONVERT,          "VK_NONCONVERT"          },
    { ACCELERATOR_VK_CODES::VK_ACCEPT,              "VK_ACCEPT"              },
    { ACCELERATOR_VK_CODES::VK_MODECHANGE,          "VK_MODECHANGE"          },
    { ACCELERATOR_VK_CODES::VK_SPACE,               "VK_SPACE"               },
    { ACCELERATOR_VK_CODES::VK_PRIOR,               "VK_PRIOR"               },
    { ACCELERATOR_VK_CODES::VK_NEXT,                "VK_NEXT"                },
    { ACCELERATOR_VK_CODES::VK_END,                 "VK_END"                 },
    { ACCELERATOR_VK_CODES::VK_HOME,                "VK_HOME"                },
    { ACCELERATOR_VK_CODES::VK_LEFT,                "VK_LEFT"                },
    { ACCELERATOR_VK_CODES::VK_UP,                  "VK_UP"                  },
    { ACCELERATOR_VK_CODES::VK_RIGHT,               "VK_RIGHT"               },
    { ACCELERATOR_VK_CODES::VK_DOWN,                "VK_DOWN"                },
    { ACCELERATOR_VK_CODES::VK_SELECT,              "VK_SELECT"              },
    { ACCELERATOR_VK_CODES::VK_PRINT,               "VK_PRINT"               },
    { ACCELERATOR_VK_CODES::VK_EXECUTE,             "VK_EXECUTE"             },
    { ACCELERATOR_VK_CODES::VK_SNAPSHOT,            "VK_SNAPSHOT"            },
    { ACCELERATOR_VK_CODES::VK_INSERT,              "VK_INSERT"              },
    { ACCELERATOR_VK_CODES::VK_DELETE,              "VK_DELETE"              },
    { ACCELERATOR_VK_CODES::VK_HELP,                "VK_HELP"                },
    { ACCELERATOR_VK_CODES::VK_0,                   "VK_0"                   },
    { ACCELERATOR_VK_CODES::VK_1,                   "VK_1"                   },
    { ACCELERATOR_VK_CODES::VK_2,                   "VK_2"                   },
    { ACCELERATOR_VK_CODES::VK_3,                   "VK_3"                   },
    { ACCELERATOR_VK_CODES::VK_4,                   "VK_4"                   },
    { ACCELERATOR_VK_CODES::VK_5,                   "VK_5"                   },
    { ACCELERATOR_VK_CODES::VK_6,                   "VK_6"                   },
    { ACCELERATOR_VK_CODES::VK_7,                   "VK_7"                   },
    { ACCELERATOR_VK_CODES::VK_8,                   "VK_8"                   },
    { ACCELERATOR_VK_CODES::VK_9,                   "VK_9"                   },
    { ACCELERATOR_VK_CODES::VK_A,                   "VK_A"                   },
    { ACCELERATOR_VK_CODES::VK_B,                   "VK_B"                   },
    { ACCELERATOR_VK_CODES::VK_C,                   "VK_C"                   },
    { ACCELERATOR_VK_CODES::VK_D,                   "VK_D"                   },
    { ACCELERATOR_VK_CODES::VK_E,                   "VK_E"                   },
    { ACCELERATOR_VK_CODES::VK_F,                   "VK_F"                   },
    { ACCELERATOR_VK_CODES::VK_G,                   "VK_G"                   },
    { ACCELERATOR_VK_CODES::VK_H,                   "VK_H"                   },
    { ACCELERATOR_VK_CODES::VK_I,                   "VK_I"                   },
    { ACCELERATOR_VK_CODES::VK_J,                   "VK_J"                   },
    { ACCELERATOR_VK_CODES::VK_K,                   "VK_K"                   },
    { ACCELERATOR_VK_CODES::VK_L,                   "VK_L"                   },
    { ACCELERATOR_VK_CODES::VK_M,                   "VK_M"                   },
    { ACCELERATOR_VK_CODES::VK_N,                   "VK_N"                   },
    { ACCELERATOR_VK_CODES::VK_O,                   "VK_O"                   },
    { ACCELERATOR_VK_CODES::VK_P,                   "VK_P"                   },
    { ACCELERATOR_VK_CODES::VK_Q,                   "VK_Q"                   },
    { ACCELERATOR_VK_CODES::VK_R,                   "VK_R"                   },
    { ACCELERATOR_VK_CODES::VK_S,                   "VK_S"                   },
    { ACCELERATOR_VK_CODES::VK_T,                   "VK_T"                   },
    { ACCELERATOR_VK_CODES::VK_U,                   "VK_U"                   },
    { ACCELERATOR_VK_CODES::VK_V,                   "VK_V"                   },
    { ACCELERATOR_VK_CODES::VK_W,                   "VK_W"                   },
    { ACCELERATOR_VK_CODES::VK_X,                   "VK_X"                   },
    { ACCELERATOR_VK_CODES::VK_Y,                   "VK_Y"                   },
    { ACCELERATOR_VK_CODES::VK_Z,                   "VK_Z"                   },
    { ACCELERATOR_VK_CODES::VK_LWIN,                "VK_LWIN"                },
    { ACCELERATOR_VK_CODES::VK_RWIN,                "VK_RWIN"                },
    { ACCELERATOR_VK_CODES::VK_APPS,                "VK_APPS"                },
    { ACCELERATOR_VK_CODES::VK_SLEEP,               "VK_SLEEP"               },
    { ACCELERATOR_VK_CODES::VK_NUMPAD0,             "VK_NUMPAD0"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD1,             "VK_NUMPAD1"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD2,             "VK_NUMPAD2"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD3,             "VK_NUMPAD3"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD4,             "VK_NUMPAD4"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD5,             "VK_NUMPAD5"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD6,             "VK_NUMPAD6"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD7,             "VK_NUMPAD7"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD8,             "VK_NUMPAD8"             },
    { ACCELERATOR_VK_CODES::VK_NUMPAD9,             "VK_NUMPAD9"             },
    { ACCELERATOR_VK_CODES::VK_MULTIPLY,            "VK_MULTIPLY"            },
    { ACCELERATOR_VK_CODES::VK_ADD,                 "VK_ADD"                 },
    { ACCELERATOR_VK_CODES::VK_SEPARATOR,           "VK_SEPARATOR"           },
    { ACCELERATOR_VK_CODES::VK_SUBTRACT,            "VK_SUBTRACT"            },
    { ACCELERATOR_VK_CODES::VK_DECIMAL,             "VK_DECIMAL"             },
    { ACCELERATOR_VK_CODES::VK_DIVIDE,              "VK_DIVIDE"              },
    { ACCELERATOR_VK_CODES::VK_F1,                  "VK_F1"                  },
    { ACCELERATOR_VK_CODES::VK_F2,                  "VK_F2"                  },
    { ACCELERATOR_VK_CODES::VK_F3,                  "VK_F3"                  },
    { ACCELERATOR_VK_CODES::VK_F4,                  "VK_F4"                  },
    { ACCELERATOR_VK_CODES::VK_F5,                  "VK_F5"                  },
    { ACCELERATOR_VK_CODES::VK_F6,                  "VK_F6"                  },
    { ACCELERATOR_VK_CODES::VK_F7,                  "VK_F7"                  },
    { ACCELERATOR_VK_CODES::VK_F8,                  "VK_F8"                  },
    { ACCELERATOR_VK_CODES::VK_F9,                  "VK_F9"                  },
    { ACCELERATOR_VK_CODES::VK_F10,                 "VK_F10"                 },
    { ACCELERATOR_VK_CODES::VK_F11,                 "VK_F11"                 },
    { ACCELERATOR_VK_CODES::VK_F12,                 "VK_F12"                 },
    { ACCELERATOR_VK_CODES::VK_F13,                 "VK_F13"                 },
    { ACCELERATOR_VK_CODES::VK_F14,                 "VK_F14"                 },
    { ACCELERATOR_VK_CODES::VK_F15,                 "VK_F15"                 },
    { ACCELERATOR_VK_CODES::VK_F16,                 "VK_F16"                 },
    { ACCELERATOR_VK_CODES::VK_F17,                 "VK_F17"                 },
    { ACCELERATOR_VK_CODES::VK_F18,                 "VK_F18"                 },
    { ACCELERATOR_VK_CODES::VK_F19,                 "VK_F19"                 },
    { ACCELERATOR_VK_CODES::VK_F20,                 "VK_F20"                 },
    { ACCELERATOR_VK_CODES::VK_F21,                 "VK_F21"                 },
    { ACCELERATOR_VK_CODES::VK_F22,                 "VK_F22"                 },
    { ACCELERATOR_VK_CODES::VK_F23,                 "VK_F23"                 },
    { ACCELERATOR_VK_CODES::VK_F24,                 "VK_F24"                 },
    { ACCELERATOR_VK_CODES::VK_NUMLOCK,             "VK_NUMLOCK"             },
    { ACCELERATOR_VK_CODES::VK_SCROLL,              "VK_SCROLL"              },
    { ACCELERATOR_VK_CODES::VK_LSHIFT,              "VK_LSHIFT"              },
    { ACCELERATOR_VK_CODES::VK_RSHIFT,              "VK_RSHIFT"              },
    { ACCELERATOR_VK_CODES::VK_LCONTROL,            "VK_LCONTROL"            },
    { ACCELERATOR_VK_CODES::VK_RCONTROL,            "VK_RCONTROL"            },
    { ACCELERATOR_VK_CODES::VK_LMENU,               "VK_LMENU"               },
    { ACCELERATOR_VK_CODES::VK_RMENU,               "VK_RMENU"               },
    { ACCELERATOR_VK_CODES::VK_BROWSER_BACK,        "VK_BROWSER_BACK"        },
    { ACCELERATOR_VK_CODES::VK_BROWSER_FORWARD,     "VK_BROWSER_FORWARD"     },
    { ACCELERATOR_VK_CODES::VK_BROWSER_REFRESH,     "VK_BROWSER_REFRESH"     },
    { ACCELERATOR_VK_CODES::VK_BROWSER_STOP,        "VK_BROWSER_STOP"        },
    { ACCELERATOR_VK_CODES::VK_BROWSER_SEARCH,      "VK_BROWSER_SEARCH"      },
    { ACCELERATOR_VK_CODES::VK_BROWSER_FAVORITES,   "VK_BROWSER_FAVORITES"   },
    { ACCELERATOR_VK_CODES::VK_BROWSER_HOME,        "VK_BROWSER_HOME"        },
    { ACCELERATOR_VK_CODES::VK_VOLUME_MUTE,         "VK_VOLUME_MUTE"         },
    { ACCELERATOR_VK_CODES::VK_VOLUME_DOWN,         "VK_VOLUME_DOWN"         },
    { ACCELERATOR_VK_CODES::VK_VOLUME_UP,           "VK_VOLUME_UP"           },
    { ACCELERATOR_VK_CODES::VK_MEDIA_NEXT_TRACK,    "VK_MEDIA_NEXT_TRACK"    },
    { ACCELERATOR_VK_CODES::VK_MEDIA_PREV_TRACK,    "VK_MEDIA_PREV_TRACK"    },
    { ACCELERATOR_VK_CODES::VK_MEDIA_STOP,          "VK_MEDIA_STOP"          },
    { ACCELERATOR_VK_CODES::VK_MEDIA_PLAY_PAUSE,    "VK_MEDIA_PLAY_PAUSE"    },
    { ACCELERATOR_VK_CODES::VK_LAUNCH_MAIL,         "VK_LAUNCH_MAIL"         },
    { ACCELERATOR_VK_CODES::VK_LAUNCH_MEDIA_SELECT, "VK_LAUNCH_MEDIA_SELECT" },
    { ACCELERATOR_VK_CODES::VK_LAUNCH_APP1,         "VK_LAUNCH_APP1"         },
    { ACCELERATOR_VK_CODES::VK_LAUNCH_APP2,         "VK_LAUNCH_APP2"         },
    { ACCELERATOR_VK_CODES::VK_OEM_1,               "VK_OEM_1"               },
    { ACCELERATOR_VK_CODES::VK_OEM_PLUS,            "VK_OEM_PLUS"            },
    { ACCELERATOR_VK_CODES::VK_OEM_COMMA,           "VK_OEM_COMMA"           },
    { ACCELERATOR_VK_CODES::VK_OEM_MINUS,           "VK_OEM_MINUS"           },
    { ACCELERATOR_VK_CODES::VK_OEM_PERIOD,          "VK_OEM_PERIOD"          },
    { ACCELERATOR_VK_CODES::VK_OEM_2,               "VK_OEM_2"               },
    { ACCELERATOR_VK_CODES::VK_OEM_4,               "VK_OEM_4"               },
    { ACCELERATOR_VK_CODES::VK_OEM_5,               "VK_OEM_5"               },
    { ACCELERATOR_VK_CODES::VK_OEM_6,               "VK_OEM_6"               },
    { ACCELERATOR_VK_CODES::VK_OEM_7,               "VK_OEM_7"               },
    { ACCELERATOR_VK_CODES::VK_OEM_8,               "VK_OEM_8"               },
    { ACCELERATOR_VK_CODES::VK_OEM_102,             "VK_OEM_102"             },
    { ACCELERATOR_VK_CODES::VK_PROCESSKEY,          "VK_PROCESSKEY"          },
    { ACCELERATOR_VK_CODES::VK_PACKET,              "VK_PACKET"              },
    { ACCELERATOR_VK_CODES::VK_ATTN,                "VK_ATTN"                },
    { ACCELERATOR_VK_CODES::VK_CRSEL,               "VK_CRSEL"               },
    { ACCELERATOR_VK_CODES::VK_EXSEL,               "VK_EXSEL"               },
    { ACCELERATOR_VK_CODES::VK_EREOF,               "VK_EREOF"               },
    { ACCELERATOR_VK_CODES::VK_PLAY,                "VK_PLAY"                },
    { ACCELERATOR_VK_CODES::VK_ZOOM,                "VK_ZOOM"                },
    { ACCELERATOR_VK_CODES::VK_NONAME,              "VK_NONAME"              },
    { ACCELERATOR_VK_CODES::VK_PA1,                 "VK_PA1"                 },
    { ACCELERATOR_VK_CODES::VK_OEM_CLEAR,           "VK_OEM_CLEAR"           },
  };
  const auto it = enumStrings.find(e);
  return it != enumStrings.end() ? it->second : "Undefined || reserved";
}

const char* to_string(ALGORITHMS e) {
  CONST_MAP(ALGORITHMS, const char*, 20) enumStrings {
    { ALGORITHMS::UNKNOWN,  "UNKNOWN"  },
    { ALGORITHMS::SHA_512,  "SHA_512"  },
    { ALGORITHMS::SHA_384,  "SHA_384"  },
    { ALGORITHMS::SHA_256,  "SHA_256"  },
    { ALGORITHMS::SHA_1,    "SHA_1"    },

    { ALGORITHMS::MD5,      "MD5"      },
    { ALGORITHMS::MD4,      "MD4"      },
    { ALGORITHMS::MD2,      "MD2"      },

    { ALGORITHMS::RSA,      "RSA"      },
    { ALGORITHMS::EC,       "EC"       },

    { ALGORITHMS::MD5_RSA,          "MD5_RSA"       },
    { ALGORITHMS::SHA1_DSA,         "SHA1_DSA"      },
    { ALGORITHMS::SHA1_RSA,         "SHA1_RSA"      },
    { ALGORITHMS::SHA_256_RSA,      "SHA_256_RSA"   },
    { ALGORITHMS::SHA_384_RSA,      "SHA_384_RSA"   },
    { ALGORITHMS::SHA_512_RSA,      "SHA_512_RSA"   },
    { ALGORITHMS::SHA1_ECDSA,       "SHA1_ECDSA"    },
    { ALGORITHMS::SHA_256_ECDSA,    "SHA_256_ECDSA" },
    { ALGORITHMS::SHA_384_ECDSA,    "SHA_384_ECDSA" },
    { ALGORITHMS::SHA_512_ECDSA,    "SHA_512_ECDSA" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

} // namespace PE
} // namespace LIEF
