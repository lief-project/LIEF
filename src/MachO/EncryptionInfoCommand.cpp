/* Copyright 2017 Zhang
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
#include "LIEF/visitors/Hash.hpp"

#include "LIEF/MachO/EncryptionInfoCommand.hpp"

namespace LIEF {
namespace MachO {

EncryptionInfoCommand::EncryptionInfoCommand(void) = default;
EncryptionInfoCommand& EncryptionInfoCommand::operator=(const EncryptionInfoCommand&) = default;
EncryptionInfoCommand::EncryptionInfoCommand(const EncryptionInfoCommand&) = default;
EncryptionInfoCommand::~EncryptionInfoCommand(void) = default;

EncryptionInfoCommand::EncryptionInfoCommand(const encryption_info_command_32 *command) :
        crypt_offset_{command->cryptoff},
        crypt_size_{command->cryptsize},
        crypt_id_{command->cryptid}
{
        this->command_ = static_cast<LOAD_COMMAND_TYPES>(command->cmd);
        this->size_    = command->cmdsize;
}

void EncryptionInfoCommand::accept(Visitor& visitor) const {
        LoadCommand::accept(visitor);
        visitor.visit(this->crypt_id());
        visitor.visit(this->crypt_size());
        visitor.visit(this->crypt_offset());
}
uint32_t EncryptionInfoCommand::crypt_offset(void) const {
        return this->crypt_offset_;
}
uint32_t EncryptionInfoCommand::crypt_size(void) const {
        return this->crypt_size_;
}
uint32_t EncryptionInfoCommand::crypt_id(void) const {
        return this->crypt_id_;
}

void EncryptionInfoCommand::crypt_offset(uint32_t offset){
        this->crypt_offset_ = offset;
}
void EncryptionInfoCommand::crypt_size(uint32_t sz){
        this->crypt_size_ = sz;
}
void EncryptionInfoCommand::crypt_id(uint32_t id){
        this->crypt_id_ = id;
}

bool EncryptionInfoCommand::operator==(const EncryptionInfoCommand& rhs) const {
        size_t hash_lhs = Hash::hash(*this);
        size_t hash_rhs = Hash::hash(rhs);
        return hash_lhs == hash_rhs;
}

bool EncryptionInfoCommand::operator!=(const EncryptionInfoCommand& rhs) const {
        return not (*this == rhs);
}

std::ostream& EncryptionInfoCommand::print(std::ostream& os) const {
        LoadCommand::print(os);
        os << "CryptID    : " << this->crypt_id() << std::endl;
        os << "CryptSize    : " << this->crypt_size() << std::endl;
        os << "CryptOffset    : " << this->crypt_offset() << std::endl;
        return os;
}


}
}
