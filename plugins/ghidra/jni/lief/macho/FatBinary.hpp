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
#include "jni/mirror.hpp"
#include "jni/iterator.hpp"

#include "jni/lief/macho/Binary.hpp"

#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Parser.hpp>

namespace lief_jni::macho {

class FatBinary : public JNI<
  FatBinary, std::unique_ptr<LIEF::MachO::FatBinary>>
{
  public:
  using JNI::JNI;
  static constexpr jni::Class kClass {
    "lief/macho/FatBinary",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  class Iterator : public lief_jni::Iterator<
    Iterator, LIEF::MachO::FatBinary::it_binaries, lief_jni::macho::Binary
  >
  {
    public:
    static constexpr jni::Class kClass {
      "lief/macho/FatBinary$Iterator",
      jni::Constructor{ jlong{} },
      jni::Field { "impl", jlong{}, }
    };

    static void jni_destroy(JNIEnv* env, jobject thiz) {
      destroy(thiz);
    }

    static int register_natives(JNIEnv* env);
  };

  static int register_natives(JNIEnv* env);

  static jobject jni_parse(JNIEnv* env, jobject thiz, jstring path) {
    jni::ThreadGuard TG;
    jni::LocalString jpath = path;
    return FatBinary::create(
      LIEF::MachO::Parser::parse(
        std::string(jpath.Pin().ToString())
      )
    );
  }

  static jobject jni_iterator(JNIEnv* env, jobject thiz) {
    return Iterator::create(std::move(from_jni(thiz)->impl().begin()));
  }

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
