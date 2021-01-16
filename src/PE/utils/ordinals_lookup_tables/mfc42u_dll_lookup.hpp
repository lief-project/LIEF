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
#ifndef LIEF_PE_MFC42U_DLL_LOOKUP_H_
#define LIEF_PE_MFC42U_DLL_LOOKUP_H_

#include <map>

namespace LIEF {
namespace PE {

static const std::map<uint32_t, const char*> mfc42u_dll_lookup {
    { 0x0005, "?classCCachedDataPathProperty@CCachedDataPathProperty@@2UCRuntimeClass@@B" },
    { 0x0006, "?classCDataPathProperty@CDataPathProperty@@2UCRuntimeClass@@B"         },
    { 0x0002, "DllCanUnloadNow"                                                       },
    { 0x0001, "DllGetClassObject"                                                     },
    { 0x0003, "DllRegisterServer"                                                     },
    { 0x0004, "DllUnregisterServer"                                                   },
};


}
}

#endif

