/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#ifndef LIEF_PE_SHCORE_DLL_LOOKUP_H_
#define LIEF_PE_SHCORE_DLL_LOOKUP_H_

#include <map>

namespace LIEF {
namespace PE {

static const std::map<uint32_t, const char*> shcore_dll_lookup {
    { 0x0002, "CommandLineToArgvW"                    },
    { 0x0003, "CreateRandomAccessStreamOnFile"        },
    { 0x0004, "CreateRandomAccessStreamOverStream"    },
    { 0x0005, "CreateStreamOverRandomAccessStream"    },
    { 0x0006, "DllCanUnloadNow"                       },
    { 0x0007, "DllGetActivationFactory"               },
    { 0x0008, "DllGetClassObject"                     },
    { 0x0009, "GetCurrentProcessExplicitAppUserModelID" },
    { 0x000a, "GetDpiForMonitor"                      },
    { 0x000b, "GetDpiForShellUIComponent"             },
    { 0x000c, "GetFeatureEnabledState"                },
    { 0x000d, "GetProcessDpiAwareness"                },
    { 0x000e, "GetProcessReference"                   },
    { 0x000f, "GetScaleFactorForDevice"               },
    { 0x0010, "GetScaleFactorForMonitor"              },
    { 0x0011, "IStream_Copy"                          },
    { 0x0012, "IStream_Read"                          },
    { 0x0013, "IStream_ReadStr"                       },
    { 0x0014, "IStream_Reset"                         },
    { 0x0015, "IStream_Size"                          },
    { 0x0016, "IStream_Write"                         },
    { 0x0017, "IStream_WriteStr"                      },
    { 0x0018, "IUnknown_AtomicRelease"                },
    { 0x0019, "IUnknown_GetSite"                      },
    { 0x001a, "IUnknown_QueryService"                 },
    { 0x001b, "IUnknown_Set"                          },
    { 0x001c, "IUnknown_SetSite"                      },
    { 0x001d, "IsOS"                                  },
    { 0x001e, "RecordFeatureError"                    },
    { 0x001f, "RecordFeatureUsage"                    },
    { 0x0020, "RegisterScaleChangeEvent"              },
    { 0x0021, "RegisterScaleChangeNotifications"      },
    { 0x0022, "RevokeScaleChangeNotifications"        },
    { 0x0023, "SHAnsiToAnsi"                          },
    { 0x0024, "SHAnsiToUnicode"                       },
    { 0x0025, "SHCopyKeyA"                            },
    { 0x0026, "SHCopyKeyW"                            },
    { 0x0027, "SHCreateMemStream"                     },
    { 0x0028, "SHCreateStreamOnFileA"                 },
    { 0x0029, "SHCreateStreamOnFileEx"                },
    { 0x002a, "SHCreateStreamOnFileW"                 },
    { 0x002b, "SHCreateThread"                        },
    { 0x002c, "SHCreateThreadRef"                     },
    { 0x002d, "SHCreateThreadWithHandle"              },
    { 0x002e, "SHDeleteEmptyKeyA"                     },
    { 0x002f, "SHDeleteEmptyKeyW"                     },
    { 0x0030, "SHDeleteKeyA"                          },
    { 0x0031, "SHDeleteKeyW"                          },
    { 0x0032, "SHDeleteValueA"                        },
    { 0x0033, "SHDeleteValueW"                        },
    { 0x0034, "SHEnumKeyExA"                          },
    { 0x0035, "SHEnumKeyExW"                          },
    { 0x0036, "SHEnumValueA"                          },
    { 0x0037, "SHEnumValueW"                          },
    { 0x0038, "SHGetThreadRef"                        },
    { 0x0039, "SHGetValueA"                           },
    { 0x003a, "SHGetValueW"                           },
    { 0x003b, "SHOpenRegStream2A"                     },
    { 0x003c, "SHOpenRegStream2W"                     },
    { 0x003d, "SHOpenRegStreamA"                      },
    { 0x003e, "SHOpenRegStreamW"                      },
    { 0x003f, "SHQueryInfoKeyA"                       },
    { 0x0040, "SHQueryInfoKeyW"                       },
    { 0x0041, "SHQueryValueExA"                       },
    { 0x0042, "SHQueryValueExW"                       },
    { 0x0043, "SHRegDuplicateHKey"                    },
    { 0x0044, "SHRegGetIntW"                          },
    { 0x0045, "SHRegGetPathA"                         },
    { 0x0046, "SHRegGetPathW"                         },
    { 0x0047, "SHRegGetValueA"                        },
    { 0x007a, "SHRegGetValueFromHKCUHKLM"             },
    { 0x0048, "SHRegGetValueW"                        },
    { 0x0049, "SHRegSetPathA"                         },
    { 0x004a, "SHRegSetPathW"                         },
    { 0x004b, "SHReleaseThreadRef"                    },
    { 0x004c, "SHSetThreadRef"                        },
    { 0x004d, "SHSetValueA"                           },
    { 0x004e, "SHSetValueW"                           },
    { 0x004f, "SHStrDupA"                             },
    { 0x0050, "SHStrDupW"                             },
    { 0x0051, "SHUnicodeToAnsi"                       },
    { 0x0052, "SHUnicodeToUnicode"                    },
    { 0x0053, "SetCurrentProcessExplicitAppUserModelID" },
    { 0x0054, "SetProcessDpiAwareness"                },
    { 0x0055, "SetProcessReference"                   },
    { 0x0056, "SubscribeFeatureStateChangeNotification" },
    { 0x0057, "UnregisterScaleChangeEvent"            },
    { 0x0058, "UnsubscribeFeatureStateChangeNotification" },
};


}
}

#endif

