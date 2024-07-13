/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/DWARF/DebugInfo.hpp"
#include "LIEF/DWARF/CompilationUnit.hpp"
#include "LIEF/DWARF/Function.hpp"
#include "LIEF/DWARF/Variable.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/Scope.hpp"
#include "LIEF/DWARF/types/ClassLike.hpp"
#include "LIEF/DWARF/types/Pointer.hpp"
#include "LIEF/DWARF/types/Const.hpp"
#include "LIEF/DWARF/types/Base.hpp"
#include "LIEF/DWARF/types/Array.hpp"

#include "logging.hpp"
#include "messages.hpp"
#include "internal_utils.hpp"

namespace LIEF::details {
class DebugInfo {};
}

namespace LIEF::dwarf {

namespace details {
class CompilationUnit {};
class CompilationUnitIt {};

class Function {};
class Parameter {};
class FunctionIt {};

class Variable {};
class VariableIt {};

class Type {};
class TypeIt {};

class Scope {};
}

namespace types::details {
class Member {};
}

// ----------------------------------------------------------------------------
// DWARF/Variable.hpp
// ----------------------------------------------------------------------------
Variable::Variable(std::unique_ptr<details::Variable>) :
  impl_(nullptr)
{}

std::string Variable::name() const {
  return "";
}

std::unique_ptr<Scope> Variable::scope() const {
  return nullptr;
}

std::string Variable::linkage_name() const {
  return "";
}

result<int64_t> Variable::address() const {
  return make_error_code(lief_errors::not_implemented);
}

result<uint64_t> Variable::size() const {
  return make_error_code(lief_errors::not_implemented);
}

bool Variable::is_constexpr() const {
  return true;
}

std::unique_ptr<Type> Variable::type() const {
  return nullptr;
}

debug_location_t Variable::debug_location() const {
  return {};
}

Variable::~Variable() = default;

Variable::Iterator::Iterator(std::unique_ptr<details::VariableIt>) :
  impl_(nullptr)
{}

Variable::Iterator::Iterator(const Iterator&) :
  impl_(nullptr)
{}

Variable::Iterator::Iterator(Iterator&&) noexcept :
  impl_(nullptr)
{}

Variable::Iterator::~Iterator() = default;

bool operator==(const Variable::Iterator&,
                const Variable::Iterator&)
{
  return true;
}

Variable::Iterator& Variable::Iterator::operator++() {
  return *this;
}

Variable::Iterator& Variable::Iterator::operator--() {
  return *this;
}

std::unique_ptr<Variable> Variable::Iterator::operator*() const {
  return nullptr;
}

// ----------------------------------------------------------------------------
// DWARF/Function.hpp
// ----------------------------------------------------------------------------
Function::~Function() = default;

std::unique_ptr<Scope> Function::scope() const {
  return nullptr;
}

std::string Function::name() const {
  return "";
}

std::string Function::linkage_name() const {
  return "";
}

result<uint64_t> Function::address() const {
  return make_error_code(lief_errors::not_implemented);
}

Function::vars_it Function::variables() const {
  return make_empty_iterator<Variable>();
}

bool Function::is_artificial() const {
  return false;
}

uint64_t Function::size() const {
  return 0;
}

std::vector<range_t> Function::ranges() const {
  return {};
}

debug_location_t Function::debug_location() const {
  return {};
}

std::unique_ptr<Type> Function::type() const {
  return nullptr;
}

std::vector<Function::Parameter> Function::parameters() const {
  return {};
}

Function::Iterator::Iterator(std::unique_ptr<details::FunctionIt>) :
  impl_(nullptr)
{}

Function::Iterator::Iterator(const Iterator&) :
  impl_(nullptr)
{}

Function::Iterator::Iterator(Iterator&&) noexcept :
  impl_(nullptr)
{}

Function::Iterator::~Iterator() = default;

bool operator==(const Function::Iterator&,
                const Function::Iterator&)
{
  return true;
}

Function::Iterator& Function::Iterator::operator++() {
  return *this;
}

Function::Iterator& Function::Iterator::operator--() {
  return *this;
}

std::unique_ptr<Function> Function::Iterator::operator*() const {
  return nullptr;
}

Function::Parameter::Parameter(std::unique_ptr<details::Parameter>) :
  impl_(nullptr)
{}

std::string Function::Parameter::name() const {
  return "";
}

std::unique_ptr<Type> Function::Parameter::type() const {
  return nullptr;
}

Function::Parameter::Parameter(Parameter&& other) noexcept = default;
Function::Parameter& Function::Parameter::operator=(Parameter&& other) noexcept = default;
Function::Parameter::~Parameter() = default;

// ----------------------------------------------------------------------------
// DWARF/DebugInfo.hpp
// ----------------------------------------------------------------------------
std::unique_ptr<DebugInfo> DebugInfo::from_file(const std::string&) {
  LIEF_ERR(DEBUG_FMT_NOT_SUPPORTED);
  return nullptr;
}

std::unique_ptr<Function> DebugInfo::find_function(const std::string&) const {
  return nullptr;
}

std::unique_ptr<Function> DebugInfo::find_function(uint64_t) const {
  return nullptr;
}

std::unique_ptr<Variable> DebugInfo::find_variable(uint64_t/*addr*/) const {
  return nullptr;
}

std::unique_ptr<Variable> DebugInfo::find_variable(const std::string&/*name*/) const {
  return nullptr;
}

std::unique_ptr<Type> DebugInfo::find_type(const std::string&/*name*/) const {
  return nullptr;
}

DebugInfo::compilation_units_it DebugInfo::compilation_units() const {
  return make_empty_iterator<CompilationUnit>();
}

// ----------------------------------------------------------------------------
// DWARF/CompilationUnit.hpp
// ----------------------------------------------------------------------------
CompilationUnit::CompilationUnit(std::unique_ptr<details::CompilationUnit>) :
  impl_(nullptr)
{}

CompilationUnit::~CompilationUnit() = default;


std::string CompilationUnit::name() const {
  return "";
}

std::string CompilationUnit::compilation_dir() const {
  return "";
}

std::string CompilationUnit::producer() const {
  return "";
}

uint64_t CompilationUnit::low_address() const {
  return 0;
}

uint64_t CompilationUnit::high_address() const {
  return 0;
}

uint64_t CompilationUnit::size() const {
  return 0;
}


std::vector<range_t> CompilationUnit::ranges() const {
  return {};
}

std::unique_ptr<Function> CompilationUnit::find_function(const std::string&/*name*/) const {
  return nullptr;
}

std::unique_ptr<Function> CompilationUnit::find_function(uint64_t/*addr*/) const {
  return nullptr;
}

std::unique_ptr<Variable> CompilationUnit::find_variable(uint64_t/*addr*/) const {
  return nullptr;
}

std::unique_ptr<Variable> CompilationUnit::find_variable(const std::string&/*name*/) const {
  return nullptr;
}

CompilationUnit::Language CompilationUnit::language() const {
  return {};
}

CompilationUnit::functions_it CompilationUnit::functions() const {
  return make_empty_iterator<Function>();
}

CompilationUnit::types_it CompilationUnit::types() const {
  return make_empty_iterator<Type>();
}

CompilationUnit::vars_it CompilationUnit::variables() const {
  return make_empty_iterator<Variable>();
}

CompilationUnit::Iterator::Iterator(std::unique_ptr<details::CompilationUnitIt>) :
  impl_(nullptr)
{}

CompilationUnit::Iterator::Iterator(const Iterator&) :
  impl_(nullptr)
{}

CompilationUnit::Iterator::Iterator(Iterator&&) noexcept :
  impl_(nullptr)
{}

CompilationUnit::Iterator::~Iterator() = default;

bool operator==(const CompilationUnit::Iterator&,
                const CompilationUnit::Iterator&)
{
  return true;
}

CompilationUnit::Iterator& CompilationUnit::Iterator::operator++() {
  return *this;
}

CompilationUnit::Iterator& CompilationUnit::Iterator::operator--() {
  return *this;
}

std::unique_ptr<CompilationUnit> CompilationUnit::Iterator::operator*() const {
  return nullptr;
}

// ----------------------------------------------------------------------------
// DWARF/Type.hpp
// ----------------------------------------------------------------------------

std::unique_ptr<Type> Type::create(std::unique_ptr<details::Type>/* impl*/) {
  return nullptr;
}

std::unique_ptr<Scope> Type::scope() const {
  return nullptr;
}

Type::KIND Type::kind() const {
  return KIND::UNKNOWN;
}

result<std::string> Type::name() const {
  return make_error_code(lief_errors::not_implemented);
}

result<uint64_t> Type::size() const {
  return make_error_code(lief_errors::not_implemented);
}

debug_location_t Type::location() const {
  return {};
}

Type::Type(std::unique_ptr<details::Type> impl) :
  impl_(std::move(impl))
{}

Type::Type(details::Type& impl) :
  impl_(impl)
{}

Type::~Type() = default;

Type::Iterator::Iterator(std::unique_ptr<details::TypeIt>) :
  impl_(nullptr)
{}

Type::Iterator::Iterator(const Iterator&) :
  impl_(nullptr)
{}

Type::Iterator::Iterator(Iterator&&) noexcept :
  impl_(nullptr)
{}

Type::Iterator::~Iterator() = default;

bool operator==(const Type::Iterator&,
                const Type::Iterator&)
{
  return true;
}

Type::Iterator& Type::Iterator::operator++() {
  return *this;
}

Type::Iterator& Type::Iterator::operator--() {
  return *this;
}

std::unique_ptr<Type> Type::Iterator::operator*() const {
  return nullptr;
}
// ----------------------------------------------------------------------------
// DWARF/Scope.hpp
// ----------------------------------------------------------------------------
Scope::~Scope() = default;
Scope::Scope(std::unique_ptr<details::Scope> impl) :
  impl_(std::move(impl))
{}

std::string Scope::name() const {
  return "";
}

std::unique_ptr<Scope> Scope::parent() const {
  return nullptr;
}

Scope::TYPE Scope::type() const {
  return TYPE::UNKNOWN;
}

std::string Scope::chained(const std::string&/* sep */) const {
  return "";
}

namespace types {
// ----------------------------------------------------------------------------
// DWARF/types/ClassLike.hpp
// ----------------------------------------------------------------------------
ClassLike::~ClassLike() = default;
Class::~Class() = default;
Structure::~Structure() = default;
Union::~Union() = default;

ClassLike::Member::~Member() = default;
ClassLike::Member::Member(std::unique_ptr<details::Member> impl) :
  impl_(std::move(impl))
{}

ClassLike::Member::Member(Member&& other) noexcept = default;
ClassLike::Member& ClassLike::Member::operator=(ClassLike::Member&& other) noexcept = default;

result<uint64_t> ClassLike::Member::offset() const {
  return make_error_code(lief_errors::not_implemented);
}

result<uint64_t> ClassLike::Member::bit_offset() const {
  return make_error_code(lief_errors::not_implemented);
}

bool ClassLike::Member::is_external() const {
  return false;
}

bool ClassLike::Member::is_declaration() const {
  return false;
}

std::unique_ptr<Type>ClassLike::Member::type() const {
  return nullptr;
}

std::string ClassLike::Member::name() const {
  return "";
}

std::vector<ClassLike::Member> ClassLike::members() const {
  return {};
}

std::unique_ptr<ClassLike::Member> ClassLike::find_member(uint64_t/*offset*/) const {
  return nullptr;
}

// ----------------------------------------------------------------------------
// DWARF/types/Pointer.hpp
// ----------------------------------------------------------------------------
Pointer::~Pointer() = default;

const Type* Pointer::underlying_type() const {
  return nullptr;
}

// ----------------------------------------------------------------------------
// DWARF/types/Const.hpp
// ----------------------------------------------------------------------------
Const::~Const() = default;

const Type* Const::underlying_type() const {
  return nullptr;
}

// ----------------------------------------------------------------------------
// DWARF/types/Base.hpp
// ----------------------------------------------------------------------------
Base::~Base() = default;


Base::ENCODING Base::encoding() const {
  return ENCODING::NONE;
}

// ----------------------------------------------------------------------------
// DWARF/types/Array.hpp
// ----------------------------------------------------------------------------
Array::~Array() = default;

const Type* Array::underlying_type() const {
  return nullptr;
}

} // namespace types



}
