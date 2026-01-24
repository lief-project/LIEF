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

#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/MetadataARM64.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::pe {

int CHPEMetadataARM64::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make("getCodeMap", "()I", jni_get_code_map),
    make("getCodeMapCount", "()I", jni_get_code_map_count),
    make("getCodeRangesToEntrypoints", "()I", jni_get_code_ranges_to_entrypoints),
    make("getRedirectionMetadata", "()I", jni_get_redirection_metadata),
    make("getOsArm64xDispatchCallNoRedirect", "()I", jni_get_os_arm64x_dispatch_call_no_redirect),
    make("getOsArm64xDispatchRet", "()I", jni_get_os_arm64x_dispatch_ret),
    make("getOsArm64xDispatchCall", "()I", jni_get_os_arm64x_dispatch_call),
    make("getOsArm64xDispatchICall", "()I", jni_get_os_arm64x_dispatch_icall),
    make("getOsArm64xDispatchIcallCfg", "()I", jni_get_os_arm64x_dispatch_icall_cfg),

    make("getAlternateEntryPoint", "()I", jni_get_alternate_entry_point),
    make("getAuxiliaryIAT", "()I", jni_get_auxiliary_iat),
    make("getCodeRangesToEntryPointsCount", "()I", jni_get_code_ranges_to_entry_points_count),
    make("getRedirectionMetadataCount", "()I", jni_get_redirection_metadata_count),
    make("getX64InformationFunctionPointer", "()I", jni_get_x64_information_function_pointer),
    make("setX64InformationFunctionPointer", "()I", jni_set_x64_information_function_pointer),
    make("getExtraRfeTable", "()I", jni_get_extra_rfe_table),
    make("getExtraRfeTableSize", "()I", jni_get_extra_rfe_table_size),
    make("getOsArm64xDispatchFptr", "()I", jni_get_os_arm64x_dispatch_fptr),
    make("getAuxiliaryIATCopy", "()I", jni_get_auxiliary_iat_copy),
    make("getAuxiliaryDelayImport", "()I", jni_get_auxiliary_delay_import),
    make("getAuxiliaryDelayImportCopy", "()I", jni_get_auxiliary_delay_import_copy),
    make("getBitfieldInfo", "()I", jni_get_bitfield_info),
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

}
