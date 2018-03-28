/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_PE_WS2_32_DLL_LOOKUP_H_
#define LIEF_PE_WS2_32_DLL_LOOKUP_H_

#include <map>
#include "frozen.hpp"

namespace LIEF {
namespace PE {

static const std::map<uint32_t, const char*> ws2_32_dll_lookup {
    { 0x001b, "FreeAddrInfoW"                },
    { 0x0018, "GetAddrInfoW"                 },
    { 0x0019, "GetNameInfoW"                 },
    { 0x01f4, "WEP"                          },
    { 0x001c, "WPUCompleteOverlappedRequest" },
    { 0x001d, "WSAAccept"                    },
    { 0x001e, "WSAAddressToStringA"          },
    { 0x001f, "WSAAddressToStringW"          },
    { 0x0066, "WSAAsyncGetHostByAddr"        },
    { 0x0067, "WSAAsyncGetHostByName"        },
    { 0x0069, "WSAAsyncGetProtoByName"       },
    { 0x0068, "WSAAsyncGetProtoByNumber"     },
    { 0x006b, "WSAAsyncGetServByName"        },
    { 0x006a, "WSAAsyncGetServByPort"        },
    { 0x0065, "WSAAsyncSelect"               },
    { 0x006c, "WSACancelAsyncRequest"        },
    { 0x0071, "WSACancelBlockingCall"        },
    { 0x0074, "WSACleanup"                   },
    { 0x0020, "WSACloseEvent"                },
    { 0x0021, "WSAConnect"                   },
    { 0x0022, "WSACreateEvent"               },
    { 0x0023, "WSADuplicateSocketA"          },
    { 0x0024, "WSADuplicateSocketW"          },
    { 0x0025, "WSAEnumNameSpaceProvidersA"   },
    { 0x0026, "WSAEnumNameSpaceProvidersW"   },
    { 0x0027, "WSAEnumNetworkEvents"         },
    { 0x0028, "WSAEnumProtocolsA"            },
    { 0x0029, "WSAEnumProtocolsW"            },
    { 0x002a, "WSAEventSelect"               },
    { 0x006f, "WSAGetLastError"              },
    { 0x002b, "WSAGetOverlappedResult"       },
    { 0x002c, "WSAGetQOSByName"              },
    { 0x002d, "WSAGetServiceClassInfoA"      },
    { 0x002e, "WSAGetServiceClassInfoW"      },
    { 0x002f, "WSAGetServiceClassNameByClassIdA" },
    { 0x0030, "WSAGetServiceClassNameByClassIdW" },
    { 0x0031, "WSAHtonl"                     },
    { 0x0032, "WSAHtons"                     },
    { 0x003a, "WSAInstallServiceClassA"      },
    { 0x003b, "WSAInstallServiceClassW"      },
    { 0x003c, "WSAIoctl"                     },
    { 0x0072, "WSAIsBlocking"                },
    { 0x003d, "WSAJoinLeaf"                  },
    { 0x003e, "WSALookupServiceBeginA"       },
    { 0x003f, "WSALookupServiceBeginW"       },
    { 0x0040, "WSALookupServiceEnd"          },
    { 0x0041, "WSALookupServiceNextA"        },
    { 0x0042, "WSALookupServiceNextW"        },
    { 0x0043, "WSANSPIoctl"                  },
    { 0x0044, "WSANtohl"                     },
    { 0x0045, "WSANtohs"                     },
    { 0x0046, "WSAProviderConfigChange"      },
    { 0x0047, "WSARecv"                      },
    { 0x0048, "WSARecvDisconnect"            },
    { 0x0049, "WSARecvFrom"                  },
    { 0x004a, "WSARemoveServiceClass"        },
    { 0x004b, "WSAResetEvent"                },
    { 0x004c, "WSASend"                      },
    { 0x004d, "WSASendDisconnect"            },
    { 0x004e, "WSASendTo"                    },
    { 0x006d, "WSASetBlockingHook"           },
    { 0x004f, "WSASetEvent"                  },
    { 0x0070, "WSASetLastError"              },
    { 0x0050, "WSASetServiceA"               },
    { 0x0051, "WSASetServiceW"               },
    { 0x0052, "WSASocketA"                   },
    { 0x0053, "WSASocketW"                   },
    { 0x0073, "WSAStartup"                   },
    { 0x0054, "WSAStringToAddressA"          },
    { 0x0055, "WSAStringToAddressW"          },
    { 0x006e, "WSAUnhookBlockingHook"        },
    { 0x0056, "WSAWaitForMultipleEvents"     },
    { 0x001a, "WSApSetPostRoutine"           },
    { 0x0057, "WSCDeinstallProvider"         },
    { 0x0058, "WSCEnableNSProvider"          },
    { 0x0059, "WSCEnumProtocols"             },
    { 0x005a, "WSCGetProviderPath"           },
    { 0x005b, "WSCInstallNameSpace"          },
    { 0x005c, "WSCInstallProvider"           },
    { 0x005d, "WSCUnInstallNameSpace"        },
    { 0x005e, "WSCUpdateProvider"            },
    { 0x005f, "WSCWriteNameSpaceOrder"       },
    { 0x0060, "WSCWriteProviderOrder"        },
    { 0x0097, "__WSAFDIsSet"                 },
    { 0x0001, "accept"                       },
    { 0x0002, "bind"                         },
    { 0x0003, "closesocket"                  },
    { 0x0004, "connect"                      },
    { 0x0061, "freeaddrinfo"                 },
    { 0x0062, "getaddrinfo"                  },
    { 0x0033, "gethostbyaddr"                },
    { 0x0034, "gethostbyname"                },
    { 0x0039, "gethostname"                  },
    { 0x0063, "getnameinfo"                  },
    { 0x0005, "getpeername"                  },
    { 0x0035, "getprotobyname"               },
    { 0x0036, "getprotobynumber"             },
    { 0x0037, "getservbyname"                },
    { 0x0038, "getservbyport"                },
    { 0x0006, "getsockname"                  },
    { 0x0007, "getsockopt"                   },
    { 0x0008, "htonl"                        },
    { 0x0009, "htons"                        },
    { 0x000b, "inet_addr"                    },
    { 0x000c, "inet_ntoa"                    },
    { 0x000a, "ioctlsocket"                  },
    { 0x000d, "listen"                       },
    { 0x000e, "ntohl"                        },
    { 0x000f, "ntohs"                        },
    { 0x0010, "recv"                         },
    { 0x0011, "recvfrom"                     },
    { 0x0012, "select"                       },
    { 0x0013, "send"                         },
    { 0x0014, "sendto"                       },
    { 0x0015, "setsockopt"                   },
    { 0x0016, "shutdown"                     },
    { 0x0017, "socket"                       },
};


}
}

#endif

