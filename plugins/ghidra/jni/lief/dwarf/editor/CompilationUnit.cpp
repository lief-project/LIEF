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

#include "jni/java/lang/Enum.hpp"

#include "jni/lief/dwarf/editor/Function.hpp"
#include "jni/lief/dwarf/editor/Variable.hpp"
#include "jni/lief/dwarf/editor/ArrayType.hpp"
#include "jni/lief/dwarf/editor/BaseType.hpp"
#include "jni/lief/dwarf/editor/EnumType.hpp"
#include "jni/lief/dwarf/editor/FunctionType.hpp"
#include "jni/lief/dwarf/editor/PointerType.hpp"
#include "jni/lief/dwarf/editor/StructType.hpp"
#include "jni/lief/dwarf/editor/Type.hpp"
#include "jni/lief/dwarf/editor/TypeDef.hpp"
#include "jni/lief/dwarf/editor/CompilationUnit.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::dwarf::editor {

void CompilationUnit::jni_set_producer(JNIEnv* env, jobject thiz, jstring producer) {
  jni::LocalString jproducer = producer;
  from_jni(thiz)->impl().set_producer(std::string(jproducer.Pin().ToString()));
}

jobject CompilationUnit::jni_create_function(JNIEnv* env, jobject thiz, jstring name) {
  jni::LocalString func_name = name;
  return Function::create(
    from_jni(thiz)->impl().create_function(
      std::string(func_name.Pin().ToString()))
  );
}

jobject CompilationUnit::jni_create_variable(JNIEnv* env, jobject thiz,
                                             jstring name)
{
  jni::LocalString jname = name;
  return Variable::create(
    from_jni(thiz)->impl().create_variable(
      std::string(jname.Pin().ToString()))
  );
}

jobject CompilationUnit::jni_create_generic_type(JNIEnv* env, jobject thiz,
                                                 jstring name)
{
  jni::LocalString jname = name;
  return Type::create(
    from_jni(thiz)->impl().create_generic_type(
      std::string(jname.Pin().ToString()))
  );
}

jobject CompilationUnit::jni_create_enum(JNIEnv* env, jobject thiz, jstring name)
{
  jni::LocalString jname = name;
  return EnumType::create<EnumType>(
    from_jni(thiz)->impl().create_enum(
      std::string(jname.Pin().ToString()))
  );
}

jobject CompilationUnit::jni_create_typedef(
  JNIEnv* env, jobject thiz, jstring name, jobject type)
{
  jni::LocalString jname = name;
  return TypeDef::create<TypeDef>(
    from_jni(thiz)->impl().create_typedef(
      std::string(jname.Pin().ToString()),
      Type::from_jni(type)->impl()
    )
  );
}

jobject CompilationUnit::jni_create_structure(
  JNIEnv* env, jobject thiz, jstring name, jobject kind)
{
  java::lang::Enum<StructType::Type> jkind = kind;
  jni::LocalString jname = name;
  return StructType::create<StructType>(
    from_jni(thiz)->impl().create_structure(
      std::string(jname.Pin().ToString()),
      jkind.as<LIEF::dwarf::editor::StructType::TYPE>()
    )
  );
}

jobject CompilationUnit::jni_create_base_type(
  JNIEnv* env, jobject thiz, jstring name, jint size, jobject encoding)
{
  java::lang::Enum<BaseType::Encoding> jenconding = encoding;
  jni::LocalString jname = name;
  return BaseType::create<BaseType>(
    from_jni(thiz)->impl().create_base_type(
      std::string(jname.Pin().ToString()),
      size,
      jenconding.as<LIEF::dwarf::editor::BaseType::ENCODING>()
    )
  );
}

jobject CompilationUnit::jni_create_function_type(
  JNIEnv* env, jobject thiz, jstring name)
{
  jni::LocalString jname = name;
  return FunctionType::create<FunctionType>(
    from_jni(thiz)->impl().create_function_type(
      std::string(jname.Pin().ToString())
    )
  );
}

jobject CompilationUnit::jni_create_pointer_type(JNIEnv* env, jobject thiz,
                                                 jobject type)
{
  return PointerType::create<PointerType>(
    from_jni(thiz)->impl().create_pointer_type(
      Type::from_jni(type)->impl()
    )
  );
}

jobject CompilationUnit::jni_create_void_type(JNIEnv* env, jobject thiz) {
  return Type::create(
    from_jni(thiz)->impl().create_void_type()
  );
}

jobject CompilationUnit::jni_create_array(
  JNIEnv* env, jobject thiz, jstring name, jobject type, jint size)
{
  jni::LocalString jname = name;
  return ArrayType::create<ArrayType>(
    from_jni(thiz)->impl().create_array(
      std::string(jname.Pin().ToString()),
      Type::from_jni(type)->impl(),
      size
    )
  );
}

int CompilationUnit::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "setProducer",
      "(Ljava/lang/String;)V",
      &jni_set_producer
    ),
    make(
      "createFunction",
      "(Ljava/lang/String;)Llief/dwarf/editor/Function;",
      &jni_create_function
    ),
    make(
      "createVariable",
      "(Ljava/lang/String;)Llief/dwarf/editor/Variable;",
      &jni_create_variable
    ),
    make(
      "createGenericType",
      "(Ljava/lang/String;)Llief/dwarf/editor/Type;",
      &jni_create_generic_type
    ),
    make(
      "createEnum",
      "(Ljava/lang/String;)Llief/dwarf/editor/EnumType;",
      &jni_create_enum
    ),
    make(
      "createTypedef",
      "(Ljava/lang/String;Llief/dwarf/editor/Type;)Llief/dwarf/editor/TypeDef;",
      &jni_create_typedef
    ),
    make(
      "createStructure",
      "(Ljava/lang/String;Llief/dwarf/editor/StructType$Type;)Llief/dwarf/editor/StructType;",
      &jni_create_structure
    ),
    make(
      "createBaseType",
      "(Ljava/lang/String;ILlief/dwarf/editor/BaseType$Encoding;)Llief/dwarf/editor/BaseType;",
      &jni_create_base_type
    ),
    make(
      "createFunctionType",
      "(Ljava/lang/String;)Llief/dwarf/editor/FunctionType;",
      &jni_create_function_type
    ),
    make(
      "createVoidType",
      "()Llief/dwarf/editor/Type;",
      &jni_create_void_type
    ),
    make(
      "createArray",
      "(Ljava/lang/String;Llief/dwarf/editor/Type;I)Llief/dwarf/editor/ArrayType;",
      &jni_create_array
    ),
    make_destroy(
      (void*)&jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  return JNI_OK;
}

}
