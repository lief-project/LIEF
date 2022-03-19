/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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

namespace LIEF {
namespace PE {

const char* mfc42u_dll_lookup(uint32_t i) {
  switch (i) {
    case 0x0005:
      return "?classCCachedDataPathProperty@CCachedDataPathProperty@@"
             "2UCRuntimeClass@@B";
    case 0x0006:
      return "?classCDataPathProperty@CDataPathProperty@@2UCRuntimeClass@@B";
    case 0x0002:
      return "DllCanUnloadNow";
    case 0x0001:
      return "DllGetClassObject";
    case 0x0003:
      return "DllRegisterServer";
    case 0x0004:
      return "DllUnregisterServer";
  }
  return nullptr;
}

}  // namespace PE
}  // namespace LIEF

#endif
