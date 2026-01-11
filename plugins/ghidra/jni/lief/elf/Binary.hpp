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
#include "jni/lief/generic/Binary.hpp"
#include "jni/lief/elf/Relocation.hpp"
#include "jni/iterator.hpp"

#include <LIEF/ELF/Binary.hpp>
#include <LIEF/ELF/Relocation.hpp>
#include <LIEF/ELF/Parser.hpp>

namespace lief_jni::elf {

class Binary : public generic::Binary {
  public:
  using lief_t = LIEF::ELF::Binary;
  using generic::Binary::Binary;
  static constexpr jni::Class kClass {
    "lief/elf/Binary",
    jni::Constructor{ jlong{} },
  };

  class RelocationsIterator : public lief_jni::Iterator<
    RelocationsIterator, LIEF::ELF::Binary::it_relocations, lief_jni::elf::Relocation
  >
  {
    public:
    static constexpr jni::Class kClass {
      "lief/elf/Binary$RelocationsIterator",
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
    return Binary::create<Binary>(
      LIEF::ELF::Parser::parse(
        std::string(jpath.Pin().ToString())
      )
    );
  }

  static jobject jni_get_relocations(JNIEnv* env, jobject thiz) {
    jni::ThreadGuard TG;
    return RelocationsIterator::create(from_jni(thiz)->cast<lief_t>().relocations());
  }


  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
