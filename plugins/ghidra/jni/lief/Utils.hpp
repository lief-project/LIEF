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

#include <LIEF/utils.hpp>
#include <LIEF/version.h>

namespace lief_jni {
class Utils {
  public:
  static constexpr jni::Class kClass {
    "lief/Utils",
  };

  class Version {
    public:
    static constexpr jni::Class kClass {
      "lief/Utils$Version",
      jni::Constructor{ jlong{}, jlong{}, jlong{}, jlong{} },
    };
  };

  static jboolean jni_is_extended(JNIEnv* /*env*/, jclass /*clazz*/) {
    jni::ThreadGuard TG;
    return LIEF::is_extended();
  }

  static jstring jni_get_extended_version_info(JNIEnv* env, jclass /*jclass*/) {
    jni::ThreadGuard TG;
    return jni::LocalString(LIEF::extended_version_info()).Release();
  }

  static jobject jni_get_extended_version(JNIEnv* env, jclass/*clazz*/) {
    jni::ThreadGuard TG;
    LIEF::lief_version_t version = LIEF::extended_version();
    return jni::LocalObject<Version::kClass>{
      (jlong)version.major, (jlong)version.minor, (jlong)version.patch,
      (jlong)version.id
    }.Release();
  }


  static jobject jni_get_version(JNIEnv* env, jclass/*clazz*/) {
    jni::ThreadGuard TG;
    LIEF::lief_version_t version = LIEF::extended_version();
    return jni::LocalObject<Version::kClass>{
      (jlong)LIEF_VERSION_MAJOR, (jlong)LIEF_VERSION_MINOR,
      (jlong)LIEF_VERSION_PATCH, (jlong)0
    }.Release();
  }


  static int register_natives(JNIEnv* env);
};
}
