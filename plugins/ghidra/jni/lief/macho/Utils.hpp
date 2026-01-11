/* Copyright 2022 - 2026 R. Thomas
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
#pragma once
#include <jni_bind.h>

#include <LIEF/MachO/utils.hpp>

namespace lief_jni::macho {
class Utils {
  public:
  static constexpr jni::Class kClass {
    "lief/macho/Utils",
  };

  static jboolean jni_is_macho(JNIEnv* /*env*/, jclass /*clazz*/,
                               jstring path)
  {
    jni::ThreadGuard TG;
    jni::LocalString jpath(path);
    return LIEF::MachO::is_macho(std::string(jpath.Pin().ToString()));
  }


  static jboolean jni_is_fat(JNIEnv* /*env*/, jclass /*clazz*/,
                             jstring path)
  {
    jni::ThreadGuard TG;
    jni::LocalString jpath(path);
    return LIEF::MachO::is_fat(std::string(jpath.Pin().ToString()));
  }

  static int register_natives(JNIEnv* env);
};
}
