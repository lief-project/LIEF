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
#include <LIEF/Abstract/Parser.hpp>
#include <array>

#include "jni/lief/dwarf/Editor.hpp"
#include "jni/lief/dwarf/editor/ArrayType.hpp"
#include "jni/lief/dwarf/editor/BaseType.hpp"
#include "jni/lief/dwarf/editor/CompilationUnit.hpp"
#include "jni/lief/dwarf/editor/EnumType.hpp"
#include "jni/lief/dwarf/editor/Function.hpp"
#include "jni/lief/dwarf/editor/FunctionType.hpp"
#include "jni/lief/dwarf/editor/PointerType.hpp"
#include "jni/lief/dwarf/editor/StructType.hpp"
#include "jni/lief/dwarf/editor/Type.hpp"
#include "jni/lief/dwarf/editor/TypeDef.hpp"
#include "jni/lief/dwarf/editor/Variable.hpp"
#include "jni/lief/generic/Binary.hpp"

#include "jni/log.hpp"
#include "jni/jni_utils.hpp"
#include "jni/java/lang/Enum.hpp"

namespace lief_jni::dwarf {

jobject Editor::jni_create_compilation_unit(JNIEnv* env, jobject thiz) {
  return editor::CompilationUnit::create(
    from_jni(thiz)->impl().create_compilation_unit()
  );
}

jobject Editor::jni_for_binary(JNIEnv* env, jclass clazz, jobject bin) {
  jni::ThreadGuard TG;
  return Editor::create(
    LIEF::dwarf::Editor::from_binary(
      generic::Binary::from_jni(bin)->impl()
    )
  );
}

jobject Editor::jni_create(JNIEnv* env, jclass clazz, jobject fmt, jobject arch) {
  java::lang::Enum<Editor::Format> jfmt = fmt;
  java::lang::Enum<Editor::Arch> jarch = arch;
  return Editor::create(
    LIEF::dwarf::Editor::create(
      jfmt.as<LIEF::dwarf::Editor::FORMAT>(),
      jarch.as<LIEF::dwarf::Editor::ARCH>()
    )
  );
}

int Editor::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "forBinary",
      "(Llief/generic/Binary;)Llief/dwarf/Editor;",
      &jni_for_binary
    ),
    make(
      "create",
      "(Llief/dwarf/Editor$Format;Llief/dwarf/Editor$Arch;)Llief/dwarf/Editor;",
      &jni_create
    ),
    make(
      "createCompilationUnit",
      "()Llief/dwarf/editor/CompilationUnit;",
      &jni_create_compilation_unit
    ),
    make(
      "write",
      "(Ljava/lang/String;)V",
      &jni_write
    ),
    make_destroy(
      &jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  editor::CompilationUnit::register_natives(env);
  editor::Function::register_natives(env);
  editor::Variable::register_natives(env);
  editor::Type::register_natives(env);
  editor::BaseType::register_natives(env);
  editor::EnumType::register_natives(env);
  editor::FunctionType::register_natives(env);
  editor::PointerType::register_natives(env);
  editor::StructType::register_natives(env);
  editor::TypeDef::register_natives(env);
  editor::ArrayType::register_natives(env);

  return JNI_OK;
}

}
