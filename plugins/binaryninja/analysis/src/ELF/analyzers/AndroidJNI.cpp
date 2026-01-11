/* Copyright 2025 - 2026 R. Thomas
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
#include "log.hpp"
#include "binaryninja/lief_utils.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "binaryninja/analysis/ELF/analyzers/AndroidJNI.hpp"

#include <binaryninja/binaryninjacore.h>
#include <binaryninja/binaryninjaapi.h>

using namespace LIEF::ELF;
using namespace BinaryNinja;
using namespace binaryninja;

namespace analysis_plugin::elf::analyzers {

static constexpr auto ANDROID_JNI_TL = "aarch64/android-jni.bntl";

bool should_change(Ref<Type> ty);
bool should_change(const Confidence<Ref<Type>>& ty);

bool should_change(Ref<Type> ty) {
  std::string type_str = ty->GetString();
  if (type_str == "jobject" || type_str == "jclass" || type_str == "JNIEnv") {
    return false;
  }

  if (!ty->IsPointer()) {
    return true;
  }

  auto child_type = ty->GetChildType();
  if (!child_type) {
    return true;
  }

  return should_change(child_type);
}

bool should_change(const Confidence<Ref<Type>>& ty) {
  std::string type_str = ty->GetString();
  if (ty.GetConfidence() != BN_FULL_CONFIDENCE) {
    return true;
  }
  return should_change(ty.GetValue());
}

static void process(FunctionParameter& original_param, FunctionParameter& new_param)  {
  if (original_param.name.starts_with("arg")) {
    original_param.name = new_param.name;
  }

  if (should_change(original_param.type)) {
    original_param.type = new_param.type;
  }
}

bool AndroidJNI::can_run(BinaryNinja::BinaryView& bv, Binary& elf) {
  return elf.is_targeting_android();
}

void AndroidJNI::init() {
  std::optional<std::string> tl = find_typelib(ANDROID_JNI_TL);
  if (!tl) {
    BN_ERR("Can't find typelib: {}", ANDROID_JNI_TL);
    return;
  }

  Ref<TypeLibrary> typelib = TypeLibrary::LoadFromFile(*tl);
  if (!typelib) {
    BN_ERR("Can't load typelibrary: {}", *tl);
    return;
  }

  if (bv_.GetTypeLibrary(typelib->GetName()) == nullptr) {
    BN_INFO("Adding typelib: {}", typelib->GetName());
    bv_.AddTypeLibrary(typelib);
  }
}

void AndroidJNI::run() {
  init();

  Ref<TagType> jni_tag = get_or_create_tag(ANDROID_JNI_FUNC_TAG);

  for (Ref<Function> F : bv_.GetAnalysisFunctionList()) {
    if (F->GetSymbol()->GetRawName() == "JNI_OnLoad") {
      process_JNI_OnLoad(*F);
    }

    if (!F->GetTagReferencesOfType(jni_tag).empty()) {
      process_JNI_function(*F);
    }
  }
}

void AndroidJNI::process_JNI_OnLoad(Function& F) {
  BN_DEBUG("Processing JNI_OnLoad: 0x{:010x}", F.GetSymbol()->GetAddress());
  Ref<Type> FTy = F.GetType();
  if (!FTy->IsFunction()) {
    BN_ERR("Expecting a function type");
    return;
  }

  QualifiedNameAndType JNI_OnLoadTy;

  std::string err;
  if (!bv_.ParseTypeString("jint JNI_OnLoad(JavaVM* vm, void* reserved)", JNI_OnLoadTy, err)) {
    BN_ERR("Can't parse JNI_OnLoad prototype: {}", err);
    return;
  }
  F.SetUserType(JNI_OnLoadTy.type);
}

void AndroidJNI::process_JNI_function(Function& F) {
  BN_DEBUG("Processing JNI Function - {}: 0x{:010x}", F.GetSymbol()->GetFullName(),
           F.GetSymbol()->GetAddress());

  Ref<Type> FTy = F.GetType();
  if (!FTy->IsFunction()) {
    BN_ERR("Expecting a function type");
    return;
  }

  FunctionParameter P0;
  {
    QualifiedNameAndType result;
    std::string err;
    if (!bv_.ParseTypeString("JNIEnv* env", result, err)) {
      BN_ERR("Can't parse JNIEnv: {}", err);
      return;
    }
    P0.name = "env";
    P0.type = result.type;
  }

  FunctionParameter P1;
  {
    QualifiedNameAndType result;
    std::string err;
    if (!bv_.ParseTypeString("jobject thiz", result, err)) {
      BN_ERR("Can't parse jobject: {}", err);
      return;
    }
    P1.name = "thiz";
    P1.type = result.type;
  }

  std::vector<FunctionParameter> params = FTy->GetParameters();
  params.resize(std::max<size_t>(params.size(), 2));

  process(params[0], P0);
  process(params[1], P1);

  F.SetUserType(Type::FunctionType(
    F.GetReturnType(),
    F.GetCallingConvention(),
    params
  ));
}

}
