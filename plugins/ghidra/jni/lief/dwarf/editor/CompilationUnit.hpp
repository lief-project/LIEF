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

#include "jni/mirror.hpp"

#include <jni_bind.h>
#include <LIEF/Abstract/Binary.hpp>

#include <LIEF/DWARF/Editor.hpp>
#include <LIEF/DWARF/editor/CompilationUnit.hpp>

namespace lief_jni::dwarf::editor {

class CompilationUnit : public JNI<
  CompilationUnit, std::unique_ptr<LIEF::dwarf::editor::CompilationUnit>>
{
  public:
  static constexpr jni::Class kClass {
    "lief/dwarf/editor/CompilationUnit",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static void jni_set_producer(JNIEnv* env, jobject thiz, jstring producer);

  static jobject jni_create_function(JNIEnv* env, jobject thiz, jstring name);

  static jobject jni_create_variable(JNIEnv* env, jobject thiz, jstring name);

  static jobject jni_create_generic_type(JNIEnv* env, jobject thiz, jstring name);

  static jobject jni_create_enum(JNIEnv* env, jobject thiz, jstring name);

  static jobject jni_create_typedef(JNIEnv* env, jobject thiz, jstring name,
                                    jobject type);

  static jobject jni_create_structure(JNIEnv* env, jobject thiz, jstring name,
                                      jobject kind);

  static jobject jni_create_base_type(JNIEnv* env, jobject thiz, jstring name,
                                      jint size, jobject encoding);

  static jobject jni_create_function_type(JNIEnv* env, jobject thiz, jstring name);

  static jobject jni_create_pointer_type(JNIEnv* env, jobject thiz, jobject type);

  static jobject jni_create_void_type(JNIEnv* env, jobject thiz);

  static jobject jni_create_array(JNIEnv* env, jobject thiz, jstring name,
                                  jobject type, jint size);

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
