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
#include "jni/lief/dwarf/editor/Type.hpp"

#include <LIEF/DWARF/editor/Variable.hpp>

namespace lief_jni::dwarf::editor {

class Variable : public JNI<
  Variable, std::unique_ptr<LIEF::dwarf::editor::Variable>>
{
  public:
  using JNI::JNI;
  static constexpr jni::Class kClass {
    "lief/dwarf/editor/Variable",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }

  static jobject jni_set_addr(JNIEnv* env, jobject thiz, jlong addr) {
    from_jni(thiz)->impl().set_addr((uint64_t)addr);
    return thiz;
  }

  static jobject jni_set_stack_offset(JNIEnv* env, jobject thiz, jlong offset) {
    from_jni(thiz)->impl().set_stack_offset((uint64_t)offset);
    return thiz;
  }

  static jobject jni_set_external(JNIEnv* env, jobject thiz) {
    from_jni(thiz)->impl().set_external();
    return thiz;
  }

  static jobject jni_set_type(JNIEnv* env, jobject thiz, jobject type) {
    from_jni(thiz)->impl().set_type(
      Type::from_jni(type)->impl()
    );
    return thiz;
  }

  static jobject jni_add_description(JNIEnv* env, jobject thiz, jstring desc) {
    jni::LocalString jdesc = desc;
    from_jni(thiz)->impl().add_description(std::string(jdesc.Pin().ToString()));
    return thiz;
  }
};
}
