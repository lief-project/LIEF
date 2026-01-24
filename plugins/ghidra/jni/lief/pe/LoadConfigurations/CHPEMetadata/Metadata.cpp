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

#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/MetadataARM64.hpp"
#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/MetadataX86.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

#include <LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataARM64.hpp>
#include <LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataX86.hpp>

namespace lief_jni::pe {

int CHPEMetadata::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "getVersion",
      "()I",
      &jni_get_version
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

  CHPEMetadataARM64::register_natives(env);
  CHPEMetadataX86::register_natives(env);

  return JNI_OK;
}

jobject CHPEMetadata::create(lief_t& impl) {
  if (auto* arm64 = impl.as<LIEF::PE::CHPEMetadataARM64>()) {
    return CHPEMetadataARM64::create<CHPEMetadataARM64>(*arm64);
  }

  if (auto* x86 = impl.as<LIEF::PE::CHPEMetadataX86>()) {
    return CHPEMetadataX86::create<CHPEMetadataX86>(*x86);
  }

  return nullptr;
}

}
