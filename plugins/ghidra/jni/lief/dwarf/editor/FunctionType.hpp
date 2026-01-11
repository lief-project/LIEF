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

#include "jni/lief/dwarf/editor/Type.hpp"

#include <LIEF/DWARF/editor/FunctionType.hpp>

namespace lief_jni::dwarf::editor {

class FunctionType : public Type {
  public:
  using Type::Type;
  using lief_t = LIEF::dwarf::editor::FunctionType;
  static constexpr jni::Class kClass {
    "lief/dwarf/editor/FunctionType",
    jni::Constructor{ jlong{} },
  };

  class Parameter : public JNI<
    Parameter, std::unique_ptr<LIEF::dwarf::editor::FunctionType::Parameter>>
  {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/FunctionType$Parameter",
      jni::Constructor{ jlong{} },
      jni::Field { "impl", jlong{}, }
    };

    static void jni_destroy(JNIEnv* env, jobject thiz) {
      destroy(thiz);
    }

    static int register_natives(JNIEnv* env);
  };

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }

  static jobject jni_set_return_type(JNIEnv* env, jobject thiz, jobject type) {
    from_jni(thiz)->cast<lief_t>().set_return_type(
      Type::from_jni(type)->impl()
    );
    return thiz;
  }

  static jobject jni_add_parameter(JNIEnv* env, jobject thiz, jobject type) {
    return Parameter::create(
      from_jni(thiz)->cast<lief_t>().add_parameter(
        Type::from_jni(type)->impl()
      )
    );
  }
};
}
