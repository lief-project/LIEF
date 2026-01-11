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

#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include <LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataARM64.hpp>

namespace lief_jni::pe {

class CHPEMetadataARM64 : public CHPEMetadata {
  public:
  using lief_t = LIEF::PE::CHPEMetadataARM64;
  using JNI::create;

  using CHPEMetadata::CHPEMetadata;

  static constexpr jni::Class kClass {
    "lief/pe/CHPEMetadataARM64",
    jni::Constructor{ jlong{} },
  };

  static jint jni_get_code_map(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().code_map();
  }

  static jint jni_get_code_map_count(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().code_map_count();
  }

  static jint jni_get_code_ranges_to_entrypoints(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().code_ranges_to_entrypoints();
  }

  static jint jni_get_redirection_metadata(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().redirection_metadata();
  }

  static jint jni_get_os_arm64x_dispatch_call_no_redirect(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().os_arm64x_dispatch_call_no_redirect();
  }

  static jint jni_get_os_arm64x_dispatch_ret(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().os_arm64x_dispatch_ret();
  }

  static jint jni_get_os_arm64x_dispatch_call(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().os_arm64x_dispatch_call();
  }

  static jint jni_get_os_arm64x_dispatch_icall(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().os_arm64x_dispatch_icall();
  }

  static jint jni_get_os_arm64x_dispatch_icall_cfg(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().os_arm64x_dispatch_icall_cfg();
  }

  static jint jni_get_alternate_entry_point(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().alternate_entry_point();
  }

  static jint jni_get_auxiliary_iat(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().auxiliary_iat();
  }

  static jint jni_get_code_ranges_to_entry_points_count(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().code_ranges_to_entry_points_count();
  }

  static jint jni_get_redirection_metadata_count(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().redirection_metadata_count();
  }

  static jint jni_get_x64_information_function_pointer(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().get_x64_information_function_pointer();
  }

  static jint jni_set_x64_information_function_pointer(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().set_x64_information_function_pointer();
  }

  static jint jni_get_extra_rfe_table(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().extra_rfe_table();
  }

  static jint jni_get_extra_rfe_table_size(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().extra_rfe_table_size();
  }

  static jint jni_get_os_arm64x_dispatch_fptr(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().os_arm64x_dispatch_fptr();
  }

  static jint jni_get_auxiliary_iat_copy(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().auxiliary_iat_copy();
  }

  static jint jni_get_auxiliary_delay_import(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().auxiliary_delay_import();
  }

  static jint jni_get_auxiliary_delay_import_copy(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().auxiliary_delay_import_copy();
  }

  static jint jni_get_bitfield_info(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().bitfield_info();
  }

  static int register_natives(JNIEnv* env);

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
