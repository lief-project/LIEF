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
#include "jni/lief/dwarf/editor/Variable.hpp"

#include <LIEF/DWARF/editor/Function.hpp>

namespace lief_jni::dwarf::editor {

class Function : public JNI<
  Function, std::unique_ptr<LIEF::dwarf::editor::Function>>
{
  public:
  using JNI::JNI;
  static constexpr jni::Class kClass {
    "lief/dwarf/editor/Function",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  class Range {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/Function$Range",
      jni::Field { "start", jlong{}, },
      jni::Field { "end", jlong{}, }
    };
  };

  class Parameter : public JNI<
    Parameter, std::unique_ptr<LIEF::dwarf::editor::Function::Parameter>>
  {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/Function$Parameter",
      jni::Constructor{ jlong{} },
      jni::Field { "impl", jlong{}, }
    };

    static void jni_destroy(JNIEnv* env, jobject thiz) {

    }

    static int register_natives(JNIEnv* env);
  };

  class LexicalBlock : public JNI<
    LexicalBlock, std::unique_ptr<LIEF::dwarf::editor::Function::LexicalBlock>>
  {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/Function$LexicalBlock",
      jni::Constructor{ jlong{} },
      jni::Field { "impl", jlong{}, }
    };

    static jobject jni_add_description(JNIEnv* env, jobject thiz, jstring desc) {
      jni::LocalString jdesc = desc;
      from_jni(thiz)->impl().add_description(std::string(jdesc.Pin().ToString()));
      return thiz;
    }

    static jobject jni_add_name(JNIEnv* env, jobject thiz, jstring name) {
      jni::LocalString jname = name;
      from_jni(thiz)->impl().add_name(std::string(jname.Pin().ToString()));
      return thiz;
    }


    static jobject jni_add_block(JNIEnv* env, jobject thiz, jlong start, jlong end) {
      return LexicalBlock::create(
        from_jni(thiz)->impl().add_block(start, end)
      );
    }

    static jobject jni_add_block_from_range(JNIEnv* env, jobject thiz,
                                            jobject ranges);

    static void jni_destroy(JNIEnv* env, jobject thiz) {
      destroy(thiz);
    }

    static int register_natives(JNIEnv* env);
  };

  class Label : public JNI<
    Label, std::unique_ptr<LIEF::dwarf::editor::Function::Label>>
  {
    public:
    static constexpr jni::Class kClass {
      "lief/dwarf/editor/Function$Label",
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

  static jobject jni_set_address(JNIEnv* env, jobject thiz, jlong addr) {
    from_jni(thiz)->impl().set_address(addr);
    return thiz;
  }

  static jobject jni_set_low_high(JNIEnv* env, jobject thiz,
                                  jlong low, jlong high)
  {
    from_jni(thiz)->impl().set_low_high(low, high);
    return thiz;
  }

  static jobject jni_set_ranges(JNIEnv* env, jobject thiz, jobject ranges);

  static jobject jni_set_exeternal(JNIEnv* env, jobject thiz) {
    from_jni(thiz)->impl().set_external();
    return thiz;
  }

  static jobject jni_add_description(JNIEnv* env, jobject thiz, jstring desc) {
    jni::LocalString jdesc = desc;
    from_jni(thiz)->impl().add_description(std::string(jdesc.Pin().ToString()));
    return thiz;
  }

  static jobject jni_set_return_type(JNIEnv* env, jobject thiz, jobject type) {
    from_jni(thiz)->impl().set_return_type(
      Type::from_jni(type)->impl()
    );
    return thiz;

  }

  static jobject
    jni_add_parameter(JNIEnv* env, jobject thiz, jstring name, jobject type)
  {
    jni::LocalString jname = name;
    return Parameter::create(
      from_jni(thiz)->impl().add_parameter(
        std::string(jname.Pin().ToString()),
        Type::from_jni(type)->impl()
      )
    );
  }

  static jobject
    jni_create_stack_variable(JNIEnv* env, jobject thiz, jstring name)
  {
    jni::LocalString jname = name;
    return Variable::create(
      from_jni(thiz)->impl().create_stack_variable(
        std::string(jname.Pin().ToString())
      )
    );
  }

  static jobject
    jni_create_lexical_block(JNIEnv* env, jobject thiz, jlong start, jlong end)
  {
    return LexicalBlock::create(
      from_jni(thiz)->impl().add_lexical_block(
        (uint64_t)start, (uint64_t)end
      )
    );
  }

  static jobject
    jni_add_label(JNIEnv* env, jobject thiz, jlong start, jstring label)
  {
    jni::LocalString jlabel = label;
    return Label::create(
      from_jni(thiz)->impl().add_label(
        (uint64_t)start,
        std::string(jlabel.Pin().ToString())
      )
    );
  }


};
}
