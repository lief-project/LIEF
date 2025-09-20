/* Copyright 2025 R. Thomas
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
#include "binaryninja/analysis/PE/TypeBuilder.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"

using namespace BinaryNinja;

namespace analysis_plugin::pe {

/* Note#packed:
 * As of BinaryNinja >= 5.1.8005 the API does not support bitfield as
 * described here: https://github.com/Vector35/binaryninja-api/issues/694
 */

Ref<Type> TypeBuilder::get_or_create(const std::string& name) {

  if (Ref<Type> type = get(name)) {
    return type;
  }

  const Ref<Architecture> default_arch = bv_.GetDefaultArchitecture();

  if (name == "IMAGE_ARM64EC_METADATA_V1") {
    StructureBuilder struct_builder;
    struct_builder
      .AddMember(u32(), "Version")
      .AddMember(RVA(), "CodeMap")
      .AddMember(u32(), "CodeMapCount")
      .AddMember(RVA(), "CodeRangesToEntryPoints")
      .AddMember(RVA(), "RedirectionMetadata")
      .AddMember(RVA(), "__os_arm64x_dispatch_call_no_redirect")
      .AddMember(RVA(), "__os_arm64x_dispatch_ret")
      .AddMember(RVA(), "__os_arm64x_dispatch_call")
      .AddMember(RVA(), "__os_arm64x_dispatch_icall")
      .AddMember(RVA(), "__os_arm64x_dispatch_icall_cfg")
      .AddMember(RVA(), "AlternateEntryPoint")
      .AddMember(RVA(), "AuxiliaryIAT")
      .AddMember(u32(), "CodeRangesToEntryPointsCount")
      .AddMember(u32(), "RedirectionMetadataCount")
      .AddMember(RVA(), "GetX64InformationFunctionPointer")
      .AddMember(RVA(), "SetX64InformationFunctionPointer")
      .AddMember(RVA(), "ExtraRFETable")
      .AddMember(u32(), "ExtraRFETableSize")
      .AddMember(RVA(), "__os_arm64x_dispatch_fptr")
      .AddMember(RVA(), "AuxiliaryIATCopy")
    ;
    Ref<Structure> S = struct_builder.Finalize();
    return create_struct(
        *S, "_" + format_type(name), format_type(name));
  }

  if (name == "IMAGE_ARM64EC_METADATA_V2") {
    Ref<Type> base = get_or_create("IMAGE_ARM64EC_METADATA_V1");
    auto base_struct = get_as<Structure>(base);
    assert(base_struct != nullptr);
    StructureBuilder builder;

    for (const StructureMember& member : base_struct->GetMembers()) {
      builder.AddMember(member.type, member.name, member.access, member.scope);
    }

    builder
      .AddMember(RVA(), "AuxDelayloadIAT")
      .AddMember(RVA(), "AuxDelayloadIATCopy")
      .AddMember(u32(), "ReservedBitField");

    Ref<Structure> S = builder.Finalize();
    return create_struct(
        *S, "_" + format_type(name), format_type(name));
  }

  if (name == "IMAGE_LOAD_CONFIG_CODE_INTEGRITY") {
    StructureBuilder builder;
    builder
      .AddMember(u16(), "Flags")
      .AddMember(u16(), "Catalog")
      .AddMember(u32(), "CatalogOffset")
      .AddMember(u32(), "Reserved");
    Ref<Structure> S = builder.Finalize();
    return create_struct(*S, format_type(name));
  }

  if (name == "IMAGE_GUARD") {
    using IMAGE_GUARD = LIEF::PE::LoadConfiguration::IMAGE_GUARD;
    EnumerationBuilder F;
    F.AddMemberWithValue(
        "IMAGE_GUARD_CF_INSTRUMENTED", (uint32_t)IMAGE_GUARD::CF_INSTRUMENTED);

    F.AddMemberWithValue(
        "IMAGE_GUARD_CFW_INSTRUMENTED", (uint32_t)IMAGE_GUARD::CFW_INSTRUMENTED);

    F.AddMemberWithValue(
        "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", (uint32_t)IMAGE_GUARD::CF_FUNCTION_TABLE_PRESENT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_SECURITY_COOKIE_UNUSED", (uint32_t)IMAGE_GUARD::SECURITY_COOKIE_UNUSED);

    F.AddMemberWithValue(
        "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", (uint32_t)IMAGE_GUARD::PROTECT_DELAYLOAD_IAT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION", (uint32_t)IMAGE_GUARD::DELAYLOAD_IAT_IN_ITS_OWN_SECTION);

    F.AddMemberWithValue(
        "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", (uint32_t)IMAGE_GUARD::CF_EXPORT_SUPPRESSION_INFO_PRESENT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION", (uint32_t)IMAGE_GUARD::CF_ENABLE_EXPORT_SUPPRESSION);

    F.AddMemberWithValue(
        "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", (uint32_t)IMAGE_GUARD::CF_LONGJUMP_TABLE_PRESENT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_RF_INSTRUMENTED", (uint32_t)IMAGE_GUARD::RF_INSTRUMENTED);

    F.AddMemberWithValue(
        "IMAGE_GUARD_RF_ENABLE", (uint32_t)IMAGE_GUARD::RF_ENABLE);

    F.AddMemberWithValue(
        "IMAGE_GUARD_RF_STRICT", (uint32_t)IMAGE_GUARD::RF_STRICT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_RETPOLINE_PRESENT", (uint32_t)IMAGE_GUARD::RETPOLINE_PRESENT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT", (uint32_t)IMAGE_GUARD::EH_CONTINUATION_TABLE_PRESENT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_XFG_ENABLED", (uint32_t)IMAGE_GUARD::XFG_ENABLED);

    F.AddMemberWithValue(
        "IMAGE_GUARD_CASTGUARD_PRESENT", (uint32_t)IMAGE_GUARD::CASTGUARD_PRESENT);

    F.AddMemberWithValue(
        "IMAGE_GUARD_MEMCPY_PRESENT", (uint32_t)IMAGE_GUARD::MEMCPY_PRESENT);

    Ref<Enumeration> enum_ = F.Finalize();
    Ref<Type> enum_ty = Type::EnumerationType(
        default_arch, enum_, /*width=*/4, /*isSigned=*/false);

    return cache_.insert({format_type(name), std::move(enum_ty)}).first->second;
  }


  if (name == "IMAGE_ARM64EC_METADATA_CODE_RANGE") {
    // See Note#packed
    StructureBuilder builder;
    builder
      .AddMember(u32(), "RVAType")
      .AddMember(u32(), "Length")
    ;

    Ref<Structure> S = builder.Finalize();
    return create_struct(
        *S, "_" + format_type(name), format_type(name));
  }

  if (name == "IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT") {
    StructureBuilder builder;
    builder
      .AddMember(RVA(), "StartRva")
      .AddMember(RVA(), "EndRva")
      .AddMember(RVA(), "EntryPoint")
    ;

    Ref<Structure> S = builder.Finalize();
    return create_struct(
        *S, "_" + format_type(name), format_type(name));
  }

  if (name == "IMAGE_ARM64EC_METADATA_REDIRECTION") {
    StructureBuilder builder;
    builder
      .AddMember(RVA(), "From")
      .AddMember(RVA(), "To")
    ;

    Ref<Structure> S = builder.Finalize();
    return create_struct(
        *S, "_" + format_type(name), format_type(name));
  }

  if (name == "IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY") {
    StructureBuilder builder;
    builder
      .AddMember(RVA(), "BeginAddress")
      .AddMember(RVA(), "UnwindData");

    Ref<Structure> S = builder.Finalize();
    return create_struct(
        *S, "_" + format_type(name), format_type(name));
  }

  if (name == "IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA") {
    // See Note#packed
    StructureBuilder builder;
    builder
      .AddMember(u32(), "HeaderData");

    Ref<Structure> S = builder.Finalize();
    return create_struct(*S, format_type(name));
  }

  if (name == "IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED") {
    // See Note#packed
    StructureBuilder builder;
    builder
      .AddMember(u32(), "ExtendedHeaderData");

    Ref<Structure> S = builder.Finalize();
    return create_struct(*S,format_type(name));
  }

  if (name == "IMAGE_ARM64_RUNTIME_FUNCTION_EXTENDED_ENTRY") {
    StructureBuilder builder;
    builder
      .AddMember(get_or_create("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA"), "base")
      .AddMember(get_or_create("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED"), "extension")
    ;

    Ref<Structure> S = builder.Finalize();
    return create_struct(*S, format_type(name));
  }


  return nullptr;
}

}
