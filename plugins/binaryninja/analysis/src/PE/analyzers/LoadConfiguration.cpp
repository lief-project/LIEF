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
#include "binaryninja/analysis/PE/TypeBuilder.hpp"
#include "binaryninja/lief_utils.hpp"
#include "LIEF/PE/Binary.hpp"
#include "binaryninja/analysis/PE/analyzers/LoadConfiguration.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

using namespace LIEF;
using namespace BinaryNinja;

namespace analysis_plugin::pe::analyzers {

bool LoadConfiguration::can_run(BinaryNinja::BinaryView& bv, LIEF::PE::Binary& pe) {
  return pe.load_configuration() != nullptr;
}

void LoadConfiguration::update_loadconfig_ty() {
  StructureBuilder lc_ty_builder;

  const Ref<Architecture> default_arch = bv_.GetDefaultArchitecture();
  Ref<Type> RVA           = type_builder_.RVA();
  Ref<Type> bn_uint32_t   = type_builder_.u32();
  Ref<Type> bn_uint16_t   = type_builder_.u16();
  Ref<Type> bn_ptr_t      = type_builder_.ptr_t();
  Ref<Type> bn_void_ptr_t = type_builder_.void_ptr_t();
  Ref<Type> bn_func_ptr_t = type_builder_.generic_func_ptr_t();

  lc_ty_builder
    .AddMember(bn_uint32_t,   "Size")
    .AddMember(bn_uint32_t,   "TimeDateStamp")
    .AddMember(bn_uint16_t,   "MajorVersion")
    .AddMember(bn_uint16_t,   "MinorVersion")
    .AddMember(bn_uint32_t,   "GlobalFlagsClear")
    .AddMember(bn_uint32_t,   "GlobalFlagsSet")
    .AddMember(bn_uint32_t,   "CriticalSectionDefaultTimeout")
    .AddMember(bn_ptr_t,      "DeCommitFreeBlockThreshold")
    .AddMember(bn_ptr_t,      "DeCommitTotalFreeThreshold")
    .AddMember(bn_void_ptr_t, "LockPrefixTable")
    .AddMember(bn_ptr_t,      "MaximumAllocationSize")
    .AddMember(bn_ptr_t,      "VirtualMemoryThreshold")
    .AddMember(bn_ptr_t,      "ProcessHeapFlags")
    .AddMember(bn_uint32_t,   "ProcessAffinityMask")
    .AddMember(bn_uint16_t,   "CSDVersion")
    .AddMember(bn_uint16_t,   "DependentLoadFlags")
    .AddMember(bn_void_ptr_t, "EditList")
    .AddMember(bn_void_ptr_t, "SecurityCookie")
  ;

  if (load_config_->se_handler_table()) {
    lc_ty_builder.AddMember(type_builder_.make_pointer(bn_ptr_t), "SEHandlerTable");
  }

  if (load_config_->se_handler_count()) {
    lc_ty_builder.AddMember(bn_ptr_t, "SEHandlerCount");
  }

  if (load_config_->guard_cf_check_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardCFCheckFunctionPointer");
  }

  if (load_config_->guard_cf_dispatch_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardCFDispatchFunctionPointer");
  }

  if (load_config_->guard_cf_function_table()) {
    lc_ty_builder.AddMember(type_builder_.make_pointer(bn_uint32_t), "SEHandlerTable");
  }

  if (load_config_->guard_cf_function_count()) {
    lc_ty_builder.AddMember(bn_ptr_t, "GuardCFFunctionCount");
  }

  if (load_config_->guard_flags()) {
    lc_ty_builder.AddMember(
        type_builder_.get_or_create("IMAGE_GUARD"), "GuardFlags");
  }

  if (load_config_->code_integrity()) {
    lc_ty_builder.AddMember(
      type_builder_.get_or_create("IMAGE_LOAD_CONFIG_CODE_INTEGRITY"), "CodeIntegrity");
  }

  if (load_config_->guard_address_taken_iat_entry_table()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "GuardAddressTakenIatEntryTable");
  }

  if (load_config_->guard_address_taken_iat_entry_count()) {
    lc_ty_builder.AddMember(bn_ptr_t, "GuardAddressTakenIatEntryCount");
  }

  if (load_config_->guard_long_jump_target_table()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "GuardLongJumpTargetTable");
  }

  if (load_config_->guard_long_jump_target_count()) {
    lc_ty_builder.AddMember(bn_ptr_t, "GuardLongJumpTargetCount");
  }

  if (load_config_->dynamic_value_reloc_table()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "DynamicValueRelocTable");
  }

  {
    auto set_default_member = [&] {
      lc_ty_builder.AddMember(bn_void_ptr_t, "CHPEMetadataPointer");
    };

    if (PE::CHPEMetadata* metadata = load_config_->chpe_metadata()) {
      if (const auto* arm64 = metadata->as<PE::CHPEMetadataARM64>()) {
        Ref<Type> ty = process(*arm64);
        if (ty) {
          lc_ty_builder.AddMember(
              type_builder_.make_const_pointer(ty), "CHPEMetadataPointer"
          );
        } else {
          set_default_member();
        }
      }
      else {
        set_default_member();
      }
    } else {
      set_default_member();
    }
  }

  if (load_config_->guard_rf_failure_routine()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardRFFailureRoutine");
  }

  if (load_config_->guard_rf_failure_routine_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardRFFailureRoutineFunctionPointer");
  }

  if (load_config_->dynamic_value_reloctable_offset()) {
    lc_ty_builder.AddMember(type_builder_.RVA(), "DynamicValueRelocTableOffset");
  }


  if (load_config_->dynamic_value_reloctable_section()) {
    lc_ty_builder.AddMember(bn_uint16_t, "DynamicValueRelocTableSection");
  }

  if (load_config_->reserved2()) {
    lc_ty_builder.AddMember(bn_uint16_t, "Reserved2");
  }

  if (load_config_->guard_rf_verify_stackpointer_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardRFVerifyStackPointerFunctionPointer");
  }

  if (load_config_->hotpatch_table_offset()) {
    lc_ty_builder.AddMember(type_builder_.RVA(), "HotPatchTableOffset");
  }

  if (load_config_->reserved3()) {
    lc_ty_builder.AddMember(bn_uint32_t, "Reserved3");
  }

  if (load_config_->enclave_configuration_ptr()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "EnclaveConfigurationPointer");
  }

  if (load_config_->volatile_metadata_pointer()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "VolatileMetadataPointer");
  }

  if (load_config_->guard_eh_continuation_table()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "GuardEHContinuationTable");
  }

  if (load_config_->guard_eh_continuation_count()) {
    lc_ty_builder.AddMember(bn_void_ptr_t, "GuardEHContinuationCount");
  }

  if (load_config_->guard_xfg_check_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardXFGCheckFunctionPointer");
  }

  if (load_config_->guard_xfg_dispatch_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardXFGDispatchFunctionPointer");
  }

  if (load_config_->guard_xfg_table_dispatch_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardXFGTableDispatchFunctionPointer");
  }

  if (load_config_->cast_guard_os_determined_failure_mode()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "CastGuardOsDeterminedFailureMode");
  }

  if (load_config_->guard_memcpy_function_pointer()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "GuardMemcpyFunctionPointer");
  }

  if (load_config_->uma_function_pointers()) {
    lc_ty_builder.AddMember(
        type_builder_.make_pointer(bn_func_ptr_t), "UmaFunctionPointers");
  }

  Ref<Structure> S = lc_ty_builder.Finalize();
  uint64_t load_config_va = translate_addr(get_va(pe_.load_config_dir()->RVA()));

  if (pe_.type() == LIEF::PE::PE_TYPE::PE32) {
    Ref<Type> ty = type_builder_.create_struct(*S,
        "_" + type_builder_.format_type("IMAGE_LOAD_CONFIG_DIRECTORY32"),
        type_builder_.format_type("IMAGE_LOAD_CONFIG_DIRECTORY32"));

    define_struct_at(load_config_va,
        ty, "__load_configuration_directory_table", /*force=*/true);
  } else {
    Ref<Type> ty = type_builder_.create_struct(*S,
        "_" + type_builder_.format_type("IMAGE_LOAD_CONFIG_DIRECTORY64"),
        type_builder_.format_type("IMAGE_LOAD_CONFIG_DIRECTORY64"));

    define_struct_at(load_config_va,
        ty, "__load_configuration_directory_table", /*force=*/true);
  }
}

Ref<Type> LoadConfiguration::process(const LIEF::PE::CHPEMetadataARM64& arm64) {
  Ref<Type> bn_func_ptr_t = type_builder_.generic_func_ptr_t();
  Ref<Type> bn_void_ptr_t = type_builder_.void_ptr_t();

  Ref<Type> ty = arm64.version() >= 2 ?
    type_builder_.get_or_create("IMAGE_ARM64EC_METADATA_V2") :
    type_builder_.get_or_create("IMAGE_ARM64EC_METADATA_V1");

  auto S = type_builder_.get_as<Structure>(ty);
  assert(S != nullptr);

  uint64_t chpe_metadata_pointer = translate_addr(*load_config_->chpe_metadata_pointer());
  define_struct_at(chpe_metadata_pointer, ty, "__image_arm64ec_metadata");

  if (arm64.code_map() > 0) {
    uint64_t code_map_addr = translate_addr(get_va(arm64.code_map()));
    define_array_at(code_map_addr,
      type_builder_.get_or_create("IMAGE_ARM64EC_METADATA_CODE_RANGE"),
      arm64.code_map_count(), "__image_arm64ec_metadata.CodeMap");
  }

  if (auto addr = arm64.code_ranges_to_entrypoints(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));

    define_array_at(taddr,
        type_builder_.get_or_create("IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT"),
        arm64.code_ranges_to_entry_points_count(),
        "__image_arm64ec_metadata.CodeRangesToEntryPoints");
  }

  if (auto addr = arm64.redirection_metadata(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));

    define_array_at(taddr,
        type_builder_.get_or_create("IMAGE_ARM64EC_METADATA_REDIRECTION"),
        arm64.redirection_metadata_count(),
        "__image_arm64ec_metadata.RedirectionMetadata");
  }

  if (auto addr = arm64.os_arm64x_dispatch_call_no_redirect(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "__os_arm64x_dispatch_call_no_redirect_ptr");
  }

  if (auto addr = arm64.os_arm64x_dispatch_ret(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "__os_arm64x_dispatch_ret_ptr");
  }

  if (auto addr = arm64.os_arm64x_dispatch_call(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "__os_arm64x_dispatch_call_ptr");
  }

  if (auto addr = arm64.os_arm64x_dispatch_icall(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "__os_arm64x_dispatch_icall_ptr");
  }

  if (auto addr = arm64.os_arm64x_dispatch_icall_cfg(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "__os_arm64x_dispatch_icall_cfg_ptr");
  }

  if (auto addr = arm64.get_x64_information_function_pointer(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "GetX64InformationFunctionPointer_ptr");
  }

  if (auto addr = arm64.set_x64_information_function_pointer(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_func_ptr_t, "SetX64InformationFunctionPointer_ptr");
  }

  if (auto addr = arm64.os_arm64x_dispatch_fptr(); addr > 0) {
    uint64_t taddr = translate_addr(get_va(addr));
    define_type_at(taddr, bn_void_ptr_t, "__os_arm64x_dispatch_fptr_ptr");
  }

  return ty;
}

void LoadConfiguration::run() {
  load_config_ = pe_.load_configuration();
  assert(load_config_ != nullptr);
  update_loadconfig_ty();
}

}
