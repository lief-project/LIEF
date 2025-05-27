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
#include "TypeEngine.hpp"
#include <LIEF/DWARF/editor/StructType.hpp>
#include <LIEF/DWARF/editor/EnumType.hpp>
#include <LIEF/DWARF/editor/TypeDef.hpp>
#include <LIEF/DWARF/editor/PointerType.hpp>
#include <LIEF/DWARF/editor/ArrayType.hpp>
#include <LIEF/DWARF/editor/FunctionType.hpp>

#include "log.hpp"

namespace bn = BinaryNinja;
namespace dw = LIEF::dwarf;

namespace dwarf_plugin {

std::string to_string(const bn::QualifiedName& name) {
  if (name.IsEmpty()) {
    return "";
  }

  if (name.size() == 1) {
    return name.GetString();
  }

  return fmt::to_string(fmt::join(name, name.GetJoinString()));
}

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
    add_type(name, *type);
  }
}

LIEF::dwarf::editor::Type& TypeEngine::add_type(
     const BinaryNinja::QualifiedName& name, const BinaryNinja::Type& type)
{
  if (auto it = mapping_.find(type.GetObject()); it != mapping_.end()) {
    return *it->second;
  }

  BNTypeClass class_type = type.GetClass();

  std::string name_str = to_string(name);

  if (name_str.empty() && class_type == IntegerTypeClass) {
    name_str = infer_interger_name(type.GetWidth(), type.IsSigned());
  }

  switch (class_type) {
    case VoidTypeClass:
      {
        BN_DEBUG("Adding void");
        std::unique_ptr<dw::editor::Type> void_ty = unit_.create_void_type();
        return *mapping_.insert(
          {type.GetObject(), std::move(void_ty)}
        ).first->second;
      }

    case BoolTypeClass:
      {
        if (name_str.empty()) {
          name_str = "bool";
        }
        BN_DEBUG("Adding {} as bool", name_str);
        std::unique_ptr<dw::editor::BaseType> btype = unit_.create_base_type(
            name_str, type.GetWidth(), dw::editor::BaseType::ENCODING::BOOLEAN
        );

        return *mapping_.insert(
          {type.GetObject(), std::move(btype)}
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
          {type.GetObject(), std::move(btype)}
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
          {type.GetObject(), std::move(float_type)}
        ).first->second;
      }

    case PointerTypeClass:
      {
        bn::Ref<bn::Type> child = type.GetChildType();
        BN_DEBUG("Adding {} as pointer", to_string(child->GetTypeName()));
        dw::editor::Type& child_pointer = add_type(child->GetTypeName(), *child);
        std::unique_ptr<dw::editor::PointerType> pointer = child_pointer.pointer_to();
        return *mapping_.insert(
          {type.GetObject(), std::move(pointer)}
        ).first->second;
      }

    case StructureTypeClass:
      {
        BN_DEBUG("Adding {} as structure", name_str);
        bn::Ref<bn::Structure> bn_struct = type.GetStructure();
        std::unique_ptr<dw::editor::StructType> struct_type;
        if (bn_struct == nullptr) {
          BN_ERR("Can't get structure for type: {}", name);
          return *mapping_.insert(
            {type.GetObject(), unit_.create_void_type()}
          ).first->second;
        }
        switch (bn_struct->GetStructureType()) {
          case ClassStructureType:
            struct_type = unit_.create_structure(name_str, dw::editor::StructType::TYPE::CLASS);
            break;

          case UnionStructureType:
            struct_type = unit_.create_structure(name_str, dw::editor::StructType::TYPE::UNION);
            break;

          case StructStructureType:
            struct_type = unit_.create_structure(name_str, dw::editor::StructType::TYPE::STRUCT);
            break;
        }

        LIEF::dwarf::editor::StructType* struct_type_ptr = struct_type.get();
        mapping_.insert({type.GetObject(), std::move(struct_type)});

        for (const bn::StructureMember& member : bn_struct->GetMembers()) {
          BN_DEBUG(" Adding {} to {}", member.name, name_str);
          bn::Ref<bn::Type> member_type = member.type;
          struct_type_ptr->add_member(member.name,
              add_type(member_type->GetTypeName() , *member_type),
              member.offset
          );
        }
        if (uint64_t width = bn_struct->GetWidth()) {
          struct_type_ptr->set_size(bn_struct->GetWidth());
        }

        return *struct_type_ptr;
      }

    case EnumerationTypeClass:
      {
        BN_DEBUG("Adding {} as enum", name_str);
        std::unique_ptr<dw::editor::EnumType> enum_type = unit_.create_enum(name_str);
        bn::Ref<bn::Enumeration> bn_enum = type.GetEnumeration();
        enum_type->set_size(type.GetWidth());
        for (const bn::EnumerationMember& e : type.GetEnumeration()->GetMembers()) {
          enum_type->add_value(e.name, e.value);
        }
        return *mapping_.insert(
          {type.GetObject(), std::move(enum_type)}
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
            {type.GetObject(), std::move(generic)}
          ).first->second;
        }

        std::string qualname_str = to_string(name);

        BN_DEBUG("name_str:             {}", name_str);
        BN_DEBUG("qualname_str:         {}", qualname_str);
        BN_DEBUG("ntr->GetName():       {}", to_string(ntr->GetName()));
        BN_DEBUG("alias->GetTypeName(): {}", to_string(alias->GetTypeName()));

        if (qualname_str != to_string(ntr->GetName())) {
          std::unique_ptr<dw::editor::TypeDef> typdef_type =
            unit_.create_typedef(to_string(ntr->GetName()),
                                 add_type(ntr->GetName(), *alias));
          return *mapping_.insert(
            {type.GetObject(), std::move(typdef_type)}
          ).first->second;;
        }

        if (auto it = mapping_.find(alias->GetObject()); it != mapping_.end()) {
          return *it->second;
        }

        return add_type(ntr->GetName(), *alias);
      }

    case ArrayTypeClass:
      {
        std::string array_name = fmt::format("__array_{}__", ++array_id_);
        BN_DEBUG("Adding array {}", array_name);
        bn::Ref<bn::Type> element_type = type.GetChildType();
        if (element_type != nullptr) {
          dw::editor::Type& dw_element_type =
            add_type(element_type->GetTypeName(), *element_type);

          std::unique_ptr<dw::editor::ArrayType> array =
            unit_.create_array(name_str, dw_element_type, type.GetElementCount());

          return *mapping_.insert(
            {type.GetObject(), std::move(array)}
          ).first->second;;
        }

        std::unique_ptr<dw::editor::Type>
          dw_element_type = unit_.create_generic_type("element_t");

        std::unique_ptr<dw::editor::ArrayType> array =
          unit_.create_array(name_str, *dw_element_type, type.GetElementCount());

        return *mapping_.insert(
          {type.GetObject(), std::move(array)}
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
          {type.GetObject(), std::move(btype)}
        ).first->second;
      }
    case FunctionTypeClass:
      {
        std::string func_type_name =
          name_str.empty() ? fmt::format("__function_{}__", ++func_id_) :
                             name_str;

        BN_DEBUG("Adding {} as function type", func_type_name);
        bn::Ref<bn::Type> ret_type = type.GetChildType();
        std::unique_ptr<dw::editor::FunctionType> func_type =
          unit_.create_function_type(func_type_name);

        if (!ret_type->IsVoid()) {
          func_type->set_return_type(add_type(ret_type->GetTypeName(), *ret_type));
        }

        for (const bn::FunctionParameter& p : type.GetParameters()) {
          func_type->add_parameter(add_type(p.name, *p.type));
        }

        return *mapping_.insert(
          {type.GetObject(), std::move(func_type)}
        ).first->second;
      }

    case VarArgsTypeClass:
      {
        BN_WARN("VarArgsTypeClass is not supported yet ({})", name_str);
        return *mapping_.insert(
          {type.GetObject(), unit_.create_generic_type(name_str)}
        ).first->second;
      }

    case ValueTypeClass:
      {
        BN_WARN("ValueTypeClass is not supported yet ({})", name_str);
        return *mapping_.insert(
          {type.GetObject(), unit_.create_generic_type(name_str)}
        ).first->second;
      }
  }
}

}
