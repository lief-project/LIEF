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
#include <array>
#include <spdlog/fmt/compile.h>

#include "jni/java/util/List.hpp"

#include "jni/lief/dwarf/editor/Function.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::dwarf::editor {

jobject Function::jni_set_ranges(JNIEnv* env, jobject thiz, jobject ranges) {
  java::util::List<Function::Range> list = ranges;
  std::vector<LIEF::dwarf::editor::Function::range_t> native_ranges;

  list.iterate([&] (jni::LocalObject<Function::Range::kClass> e) {
    native_ranges.push_back(
      LIEF::dwarf::editor::Function::range_t {
        (uint64_t)e.Access<"start">().Get(), (uint64_t)e.Access<"end">().Get(),
      }
    );
  });

  from_jni(thiz)->impl().set_ranges(native_ranges);
  return thiz;
}


int Function::Parameter::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make_destroy(
      &jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  return JNI_OK;
}

jobject Function::LexicalBlock::jni_add_block_from_range(
    JNIEnv* env, jobject thiz, jobject ranges)
{
  java::util::List<Function::Range> list = ranges;
  std::vector<LIEF::dwarf::editor::Function::range_t> native_ranges;

  list.iterate([&] (jni::LocalObject<Function::Range::kClass> e) {
    native_ranges.push_back(
      LIEF::dwarf::editor::Function::range_t {
        (uint64_t)e.Access<"start">().Get(), (uint64_t)e.Access<"end">().Get(),
      }
    );
  });

  return LexicalBlock::create(from_jni(thiz)->impl().add_block(native_ranges));
}

int Function::LexicalBlock::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "addDescription",
      "(Ljava/lang/String;)Llief/dwarf/editor/Function$LexicalBlock;",
      &jni_add_description
    ),
    make(
      "addName",
      "(Ljava/lang/String;)Llief/dwarf/editor/Function$LexicalBlock;",
      &jni_add_name
    ),
    make(
      "addBlock",
      "(JJ)Llief/dwarf/editor/Function$LexicalBlock;",
      &jni_add_block
    ),
    make(
      "addBlock",
      "(Ljava/util/List;)Llief/dwarf/editor/Function$LexicalBlock;",
      &jni_add_block_from_range
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

  return JNI_OK;
}

int Function::Label::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make_destroy(
      &jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  return JNI_OK;
}


int Function::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "setAddress",
      "(J)Llief/dwarf/editor/Function;",
      &jni_set_address
    ),
    make(
      "setLowHigh",
      "(JJ)Llief/dwarf/editor/Function;",
      &jni_set_low_high
    ),
    make(
      "setRanges",
      "(Ljava/util/List;)Llief/dwarf/editor/Function;",
      &jni_set_ranges
    ),
    make(
      "setExternal",
      "()Llief/dwarf/editor/Function;",
      &jni_set_exeternal
    ),
    make(
      "setReturnType",
      "(Llief/dwarf/editor/Type;)Llief/dwarf/editor/Function;",
      &jni_set_return_type
    ),
    make(
      "addParameter",
      "(Ljava/lang/String;Llief/dwarf/editor/Type;)Llief/dwarf/editor/Function$Parameter;",
      &jni_add_parameter
    ),
    make(
      "createStackVariable",
      "(Ljava/lang/String;)Llief/dwarf/editor/Variable;",
      &jni_create_stack_variable
    ),
    make(
      "createStackVariable",
      "(Ljava/lang/String;)Llief/dwarf/editor/Variable;",
      &jni_create_stack_variable
    ),
    make(
      "addLexicalBlock",
      "(JJ)Llief/dwarf/editor/Function$LexicalBlock;",
      &jni_create_lexical_block
    ),
    make(
      "addLabel",
      "(JLjava/lang/String;)Llief/dwarf/editor/Function$Label;",
      &jni_add_label
    ),
    make(
      "addDescription",
      "(Ljava/lang/String;)Llief/dwarf/editor/Function;",
      &jni_add_description
    ),
    make_destroy(
      &jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  Parameter::register_natives(env);
  LexicalBlock::register_natives(env);
  Label::register_natives(env);

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  return JNI_OK;
}

}
