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
#include "binaryninja/dwarf-export/TypeEngine.hpp"
#include <LIEF/DWARF/editor/StructType.hpp>
#include <LIEF/DWARF/editor/EnumType.hpp>
#include <LIEF/DWARF/editor/TypeDef.hpp>
#include <LIEF/DWARF/editor/PointerType.hpp>
#include <LIEF/DWARF/editor/ArrayType.hpp>
#include <LIEF/DWARF/editor/FunctionType.hpp>

#include "binaryninja/api_compat.hpp"
#include "binaryninja/lief_utils.hpp"

#include "binaryninja/dwarf-export/log.hpp"

namespace bn = BinaryNinja;
namespace dw = LIEF::dwarf;

namespace dwarf_plugin {

using namespace binaryninja;

std::string infer_interger_name(size_t width, bool is_signed) {
  if (width == sizeof(uint8_t)) {
    return is_signed ? "int8_t" : "uint8_t";
  }

  if (width == sizeof(uint16_t)) {
    return is_signed ? "int16_t" : "uint16_t";
  }

  if (width == sizeof(uint32_t)) {
    return is_signed ? "int32_t" : "uint32_t";
  }

  if (width == sizeof(uint64_t)) {
    return is_signed ? "int64_t" : "uint64_t";
  }

  if (width == /* uint128_t */ 16) {
    return is_signed ? "int128_t" : "uint128_t";
  }

  return "";
}

void TypeEngine::init() {
  for (const auto& [name, type] : bv_.GetTypes()) {
    add_type(*type);
  }
}

LIEF::dwarf::editor::Type& TypeEngine::add_type(const BinaryNinja::Type& type) {
  std::string name_str = type.GetString(bv_.GetDefaultPlatform());

  if (auto it = mapping_.find(name_str); it != mapping_.end()) {
    return *it->second;
  }

  BNTypeClass class_type = type.GetClass();

  switch (class_type) {
    case VoidTypeClass:
      {
        BN_DEBUG("Adding void");
        std::unique_ptr<dw::editor::Type> void_ty = unit_.create_void_type();
        return *mapping_.insert(
          {name_str, std::move(void_ty)}
        ).first->second;
      }

    case BoolTypeClass:
      {
        BN_DEBUG("Adding {} as bool", name_str);
        std::unique_ptr<dw::editor::BaseType> btype = unit_.create_base_type(
            name_str, type.GetWidth(), dw::editor::BaseType::ENCODING::BOOLEAN
        );

        return *mapping_.insert(
          {name_str, std::move(btype)}
        ).first->second;
      }

    case IntegerTypeClass:
      {
        BN_DEBUG("Adding {} as integer", name_str);
        std::unique_ptr<dw::editor::BaseType> btype = unit_.create_base_type(
            name_str, type.GetWidth(),
            type.IsSigned() ? dw::editor::BaseType::ENCODING::SIGNED :
                              dw::editor::BaseType::ENCODING::UNSIGNED);
        return *mapping_.insert(
          {name_str, std::move(btype)}
        ).first->second;
      }

    case FloatTypeClass:
      {
        BN_DEBUG("Adding {} as float ({})", name_str, type.GetWidth());
        const size_t width = type.GetWidth();
        if (name_str.empty()) {
          if (width == 4) {
            name_str = "float";
          } else if (width == 8) {
            name_str = "double";
          } else {
            name_str = fmt::format("float{}", width);
          }
        }
        std::unique_ptr<dw::editor::BaseType> float_type = unit_.create_base_type(
            name_str, type.GetWidth(), dw::editor::BaseType::ENCODING::FLOAT);
        return *mapping_.insert(
          {name_str, std::move(float_type)}
        ).first->second;
      }

    case PointerTypeClass:
      {
        auto child = type.GetChildType();
        BN_DEBUG("Adding {} as pointer ({})",
            child->GetString(bv_.GetDefaultPlatform()), name_str);
        dw::editor::Type& child_pointer = add_type(api_compat::get_type(child));
        std::unique_ptr<dw::editor::PointerType> pointer = child_pointer.pointer_to();
        return *mapping_.insert(
          {name_str, std::move(pointer)}
        ).first->second;
      }

    case StructureTypeClass:
      {
        std::string struct_name = type.GetStructureName().GetString();
        BN_DEBUG("Adding {} as structure ({})", name_str, struct_name);
        bn::Ref<bn::Structure> bn_struct = type.GetStructure();

        if (bn_struct == nullptr) {
          BN_ERR("Can't get structure for type: {} ({})", struct_name, name_str);
          return *mapping_.insert(
            {name_str, unit_.create_void_type()}
          ).first->second;
        }
        std::unique_ptr<dw::editor::StructType> struct_type;

        switch (bn_struct->GetStructureType()) {
          case ClassStructureType:
            struct_type = unit_.create_structure(struct_name, dw::editor::StructType::TYPE::CLASS);
            break;

          case UnionStructureType:
            struct_type = unit_.create_structure(struct_name, dw::editor::StructType::TYPE::UNION);
            break;

          case StructStructureType:
            struct_type = unit_.create_structure(struct_name, dw::editor::StructType::TYPE::STRUCT);
            break;
        }

        if (uint64_t width = bn_struct->GetWidth()) {
          BN_DEBUG("{}: {} bytes", struct_name, bn_struct->GetWidth());
          struct_type->set_size(bn_struct->GetWidth());
        }

        LIEF::dwarf::editor::StructType* struct_type_ptr = struct_type.get();

        if (!struct_name.empty()) {
          mapping_.insert({name_str, std::move(struct_type)});
        } else {
          anon_types_.push_back(std::move(struct_type));
        }

        for (const bn::StructureMember& member : bn_struct->GetMembers()) {
          BN_DEBUG(" Adding {} to {}", member.name, struct_name);
          add_member(member, *struct_type_ptr);
        }

        return *struct_type_ptr;
      }

    case EnumerationTypeClass:
      {
        // NOTE(romain): Yes, this is intended to use GetStructureName to access
        // the enum name
        const std::string& enum_name = type.GetStructureName().GetString();
        BN_DEBUG("Adding {} as enum ({})", enum_name, name_str);
        std::unique_ptr<dw::editor::EnumType> enum_type = unit_.create_enum(enum_name);
        bn::Ref<bn::Enumeration> bn_enum = type.GetEnumeration();
        enum_type->set_size(type.GetWidth());

        switch (type.GetWidth()) {
          case sizeof(uint8_t):
            {
              enum_type->set_underlying_type(
                  *unit_.create_base_type("uint8_t", sizeof(uint8_t),
                    LIEF::dwarf::editor::BaseType::ENCODING::UNSIGNED));
              break;
            }

          case sizeof(uint16_t):
            {
              enum_type->set_underlying_type(
                  *unit_.create_base_type("uint16_t", sizeof(uint16_t),
                    LIEF::dwarf::editor::BaseType::ENCODING::UNSIGNED));
              break;
            }

          case sizeof(uint32_t):
            {
              enum_type->set_underlying_type(
                  *unit_.create_base_type("uint32_t", sizeof(uint32_t),
                    LIEF::dwarf::editor::BaseType::ENCODING::UNSIGNED));
              break;
            }

          case sizeof(uint64_t):
            {
              enum_type->set_underlying_type(
                  *unit_.create_base_type("uint64_t", sizeof(uint64_t),
                    LIEF::dwarf::editor::BaseType::ENCODING::UNSIGNED));
              break;
            }

          default:
            break;
        }

        for (const bn::EnumerationMember& e : type.GetEnumeration()->GetMembers()) {
          enum_type->add_value(e.name, e.value);
        }

        if (enum_name.empty()) {
          return *anon_types_.insert(anon_types_.end(), std::move(enum_type))->get();
        }

        return *mapping_.insert(
          {name_str, std::move(enum_type)}
        ).first->second;
      }

    case NamedTypeReferenceClass:
      {
        bn::Ref<bn::NamedTypeReference> ntr = type.GetNamedTypeReference();
        BN_DEBUG("Adding typedef: {} ({})", ntr->GetName(), ntr->GetTypeId());
        bn::Ref<bn::Type> alias = bv_.GetTypeByRef(ntr);

        if (!alias) {
          BN_ERR("Can't resolve the typedef of {}", name_str);
          std::unique_ptr<dw::editor::Type> generic = unit_.create_generic_type(name_str);
          return *mapping_.insert(
            {name_str, std::move(generic)}
          ).first->second;
        }

        std::string alias_name = alias->GetString(bv_.GetDefaultPlatform());

        BN_DEBUG("name_str:             {}", name_str);
        BN_DEBUG("ntr->GetName():       {}", binaryninja::to_string(ntr->GetName()));
        BN_DEBUG("alias->GetTypeName(): {}", binaryninja::to_string(alias->GetTypeName()));
        BN_DEBUG("alias->GetString():   {}", alias_name);

        if (alias_name != binaryninja::to_string(ntr->GetName())) {
          std::unique_ptr<dw::editor::TypeDef> typdef_type =
            unit_.create_typedef(binaryninja::to_string(ntr->GetName()),
                                 add_type(*alias));
          return *mapping_.insert(
            {name_str, std::move(typdef_type)}
          ).first->second;;
        }

        if (auto it = mapping_.find(alias->GetString(bv_.GetDefaultPlatform())); it != mapping_.end()) {
          return *it->second;
        }

        return add_type(*alias);
      }

    case ArrayTypeClass:
      {
        std::string array_name = fmt::format("__array_{}__", ++array_id_);
        BN_DEBUG("Adding array {}", array_name);
        auto element_type = type.GetChildType();
        if (api_compat::as_bool(element_type)) {
          dw::editor::Type& dw_element_type = add_type(api_compat::get_type(element_type));

          std::unique_ptr<dw::editor::ArrayType> array =
            unit_.create_array(name_str, dw_element_type, type.GetElementCount());

          return *mapping_.insert(
            {name_str, std::move(array)}
          ).first->second;;
        }

        std::unique_ptr<dw::editor::Type>
          dw_element_type = unit_.create_generic_type("element_t");

        std::unique_ptr<dw::editor::ArrayType> array =
          unit_.create_array(name_str, *dw_element_type, type.GetElementCount());

        return *mapping_.insert(
          {name_str, std::move(array)}
        ).first->second;
      }

    case WideCharTypeClass:
      {
        BN_DEBUG("Adding {} as widechar", name_str);
        std::unique_ptr<dw::editor::BaseType> btype = unit_.create_base_type(
            name_str, type.GetWidth(),
            type.IsSigned() ? dw::editor::BaseType::ENCODING::SIGNED_CHAR :
                              dw::editor::BaseType::ENCODING::UNSIGNED_CHAR);
        return *mapping_.insert(
          {name_str, std::move(btype)}
        ).first->second;
      }
    case FunctionTypeClass:
      {
        std::string func_type_name =
          name_str.empty() ? fmt::format("__function_{}__", ++func_id_) :
                             name_str;

        BN_DEBUG("Adding {} as function type", func_type_name);
        auto ret_type = type.GetChildType();
        std::unique_ptr<dw::editor::FunctionType> func_type =
          unit_.create_function_type(func_type_name);

        if (!ret_type->IsVoid()) {
          func_type->set_return_type(add_type(api_compat::get_type(ret_type)));
        }

        for (const bn::FunctionParameter& p : type.GetParameters()) {
          func_type->add_parameter(add_type(api_compat::get_type(p.type)));
        }

        return *mapping_.insert(
          {name_str, std::move(func_type)}
        ).first->second;
      }

    case VarArgsTypeClass:
      {
        BN_WARN("VarArgsTypeClass is not supported yet ({})", name_str);
        return *mapping_.insert(
          {name_str, unit_.create_generic_type(name_str)}
        ).first->second;
      }

    case ValueTypeClass:
      {
        BN_WARN("ValueTypeClass is not supported yet ({})", name_str);
        return *mapping_.insert(
          {name_str, unit_.create_generic_type(name_str)}
        ).first->second;
      }
  }
}

void TypeEngine::add_member(const BinaryNinja::StructureMember& member,
                            LIEF::dwarf::editor::StructType& S)
{

#if BN_BITFIELD_SUPPORT
  auto member_type = member.type;
  if (member.bitWidth > 0) {
    S.add_bitfield(member.name,
      add_type(api_compat::get_type(member_type)),
        member.bitWidth, member.offset * 8 + member.bitPosition
    );
    return;
  }

  S.add_member(member.name,
    add_type(api_compat::get_type(member_type)), member.offset
  );
#else
  auto member_type = member.type;
  S.add_member(member.name,
    add_type(api_compat::get_type(member_type)), member.offset
  );
#endif
}

}
