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
#include "jni/canbe_unique.hpp"

#include "jni/java/util/Optional.hpp"
#include "jni/java/util/OptionalInt.hpp"
#include "jni/java/util/OptionalLong.hpp"

#include "jni/lief/pe/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include "jni/lief/pe/CodeIntegrity.hpp"

#include <LIEF/PE/LoadConfigurations.hpp>

namespace lief_jni::pe {

class LoadConfiguration : public JNI<
  LoadConfiguration, canbe_unique<LIEF::PE::LoadConfiguration>>
{
  public:
  using lief_t = LIEF::PE::LoadConfiguration;

  static constexpr jni::Class kClass {
    "lief/pe/LoadConfiguration",
    jni::Constructor{ jlong{} },
    jni::Field { "impl", jlong{}, }
  };

  static int register_natives(JNIEnv* env);

  static jint jni_get_size(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().size();
  }

  static jint jni_get_timedatestamp(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().timedatestamp();
  }

  static jshort jni_get_minor_version(JNIEnv* env, jobject thiz) {
    return (jshort)from_jni(thiz)->cast<lief_t>().minor_version();
  }

  static jshort jni_get_major_version(JNIEnv* env, jobject thiz) {
    return (jshort)from_jni(thiz)->cast<lief_t>().major_version();
  }

  static jint jni_get_global_flags_clear(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().global_flags_clear();
  }

  static jint jni_get_global_flags_set(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().global_flags_set();
  }

  static jint jni_get_critical_section_default_timeout(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().critical_section_default_timeout();
  }

  static jlong jni_get_decommit_free_block_threshold(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().decommit_free_block_threshold();
  }

  static jlong jni_get_decommit_total_free_threshold(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().decommit_total_free_threshold();
  }

  static jlong jni_get_lock_prefix_table(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().lock_prefix_table();
  }

  static jlong jni_get_maximum_allocation_size(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().maximum_allocation_size();
  }

  static jlong jni_get_virtual_memory_threshold(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().virtual_memory_threshold();
  }

  static jlong jni_get_process_affinity_mask(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().process_affinity_mask();
  }

  static jint jni_get_process_heap_flags(JNIEnv* env, jobject thiz) {
    return (jint)from_jni(thiz)->cast<lief_t>().process_heap_flags();
  }

  static jshort jni_get_csd_version(JNIEnv* env, jobject thiz) {
    return (jshort)from_jni(thiz)->cast<lief_t>().csd_version();
  }

  static jshort jni_get_dependent_load_flags(JNIEnv* env, jobject thiz) {
    return (jshort)from_jni(thiz)->cast<lief_t>().dependent_load_flags();
  }

  static jlong jni_get_editlist(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().editlist();
  }

  static jlong jni_get_security_cookie(JNIEnv* env, jobject thiz) {
    return (jlong)from_jni(thiz)->cast<lief_t>().security_cookie();
  }

  static jobject jni_get_seh_table(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().se_handler_table()
    );
  }

  static jobject jni_get_seh_count(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().se_handler_count()
    );
  }

  static jobject jni_get_guard_cf_check_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_cf_check_function_pointer()
    );
  }

  static jobject jni_get_guard_cf_dispatch_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_cf_dispatch_function_pointer()
    );
  }

  static jobject jni_get_guard_cf_function_table(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_cf_function_table()
    );
  }

  static jobject jni_get_guard_cf_function_count(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_cf_function_count()
    );
  }

  static jobject jni_get_guard_flags(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_flags()
    );
  }

  static jobject jni_get_code_integrity(JNIEnv* env, jobject thiz) {
    return java::util::make_optional<CodeIntegrity>(
        from_jni(thiz)->cast<lief_t>().code_integrity()
    );
  }

  static jobject jni_get_guard_address_taken_iat_entry_table(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_address_taken_iat_entry_table()
    );
  }

  static jobject jni_get_guard_address_taken_iat_entry_count(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_address_taken_iat_entry_count()
    );
  }

  static jobject jni_get_guard_long_jump_target_table(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_long_jump_target_table()
    );
  }


  static jobject jni_get_guard_long_jump_target_count(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_long_jump_target_count()
    );
  }

  static jobject jni_get_dynamic_value_reloc_table(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().dynamic_value_reloc_table()
    );
  }


  static jobject jni_get_chpe_metadata_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().chpe_metadata_pointer()
    );
  }


  static jobject jni_get_chpe_metadata(JNIEnv* env, jobject thiz) {
    return java::util::make_optional<CHPEMetadata>(
        from_jni(thiz)->cast<lief_t>().chpe_metadata());
  }

  static jobject jni_get_guard_rf_failure_routine(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_rf_failure_routine()
    );
  }

  static jobject jni_get_guard_rf_failure_routine_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_rf_failure_routine_function_pointer()
    );
  }

  static jobject jni_get_dynamic_value_reloctable_offset(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().dynamic_value_reloctable_offset()
    );
  }

  static jobject jni_get_dynamic_value_reloctable_section(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      (LIEF::optional<uint32_t>)from_jni(thiz)->cast<lief_t>().dynamic_value_reloctable_section()
    );
  }

  static jobject jni_get_reserved2(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      (LIEF::optional<uint32_t>)from_jni(thiz)->cast<lief_t>().reserved2()
    );
  }

  static jobject jni_get_guard_rf_verify_stack_pointer_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_rf_verify_stackpointer_function_pointer()
    );
  }

  static jobject jni_get_hot_patch_table_offset(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().hotpatch_table_offset()
    );
  }

  static jobject jni_get_reserved3(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().reserved3()
    );
  }

  static jobject jni_get_enclave_configuration_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().enclave_configuration_ptr()
    );
  }

  static jobject jni_get_volatile_metadata_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().volatile_metadata_pointer()
    );
  }

  static jobject jni_get_guard_eh_continuation_table(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_eh_continuation_table()
    );
  }

  static jobject jni_get_guard_eh_continuation_count(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_eh_continuation_count()
    );
  }

  static jobject jni_get_guard_xfg_check_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_xfg_check_function_pointer()
    );
  }

  static jobject jni_get_guard_xfg_dispatch_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_xfg_dispatch_function_pointer()
    );
  }

  static jobject jni_get_guard_xfg_table_dispatch_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_xfg_table_dispatch_function_pointer()
    );
  }

  static jobject jni_get_cast_guard_os_determined_failure_mode(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().cast_guard_os_determined_failure_mode()
    );
  }

  static jobject jni_get_guard_memcpy_function_pointer(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().guard_memcpy_function_pointer()
    );
  }

  static jobject jni_get_uma_function_pointers(JNIEnv* env, jobject thiz) {
    return java::util::make_optional(
      from_jni(thiz)->cast<lief_t>().uma_function_pointers()
    );
  }

  static void jni_destroy(JNIEnv* env, jobject thiz) {
    destroy(thiz);
  }
};
}
