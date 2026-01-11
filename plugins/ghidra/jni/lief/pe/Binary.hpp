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
#include "jni/java/util/Optional.hpp"
#include "jni/iterator.hpp"

#include "jni/lief/pe/LoadConfiguration.hpp"
#include "jni/lief/pe/DataDirectory.hpp"
#include "jni/lief/pe/ExceptionInfo.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Parser.hpp>

namespace lief_jni::pe {

class Binary : public generic::Binary {
  public:
  using lief_t = LIEF::PE::Binary;

  using generic::Binary::Binary;
  static constexpr jni::Class kClass {
    "lief/pe/Binary",
    jni::Constructor{ jlong{} },
  };

  class ExceptionsIterator : public lief_jni::Iterator<
    ExceptionsIterator, LIEF::PE::Binary::it_exceptions, lief_jni::pe::ExceptionInfo
  >
  {
    public:
    static constexpr jni::Class kClass {
      "lief/pe/Binary$ExceptionsIterator",
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
      LIEF::PE::Parser::parse(
        std::string(jpath.Pin().ToString()),
        LIEF::PE::ParserConfig::all()
      )
    );
  }

  static jobject jni_get_load_configuration(JNIEnv* env, jobject thiz) {
    jni::ThreadGuard TG;
    return java::util::make_optional<LoadConfiguration>(
        from_jni(thiz)->cast<lief_t>().load_configuration());
  }

  static jobject jni_get_load_configuration_dir(JNIEnv* env, jobject thiz) {
    jni::ThreadGuard TG;
    return java::util::make_optional<DataDirectory>(
        from_jni(thiz)->cast<lief_t>().load_config_dir());
  }
  static jobject jni_get_exceptions(JNIEnv* env, jobject thiz) {
    jni::ThreadGuard TG;
    return ExceptionsIterator::create(from_jni(thiz)->cast<lief_t>().exceptions());
  }

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
