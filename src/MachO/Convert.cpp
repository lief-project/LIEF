#include "LIEF/BinaryStream/Convert.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/MachO/Structures.hpp"

/* In place conversions for BinaryStream/VectorStream data */

namespace LIEF {
namespace Convert {

template<>
void swap_endian<LIEF::MachO::super_blob>(LIEF::MachO::super_blob* sb) {
  sb->magic  = BinaryStream::swap_endian(sb->magic);
  sb->length = BinaryStream::swap_endian(sb->length);
  sb->count  = BinaryStream::swap_endian(sb->count);
}

template<>
void swap_endian<LIEF::MachO::blob_index>(LIEF::MachO::blob_index* bi) {
  bi->type   = BinaryStream::swap_endian(bi->type);
  bi->offset = BinaryStream::swap_endian(bi->offset);
}

template<>
void swap_endian<LIEF::MachO::code_directory>(LIEF::MachO::code_directory* cd) {
  cd->magic            = BinaryStream::swap_endian(cd->magic);
  cd->length           = BinaryStream::swap_endian(cd->length);
  cd->version          = BinaryStream::swap_endian(cd->version);
  cd->flags            = BinaryStream::swap_endian(cd->flags);
  cd->hash_offset      = BinaryStream::swap_endian(cd->hash_offset);
  cd->ident_offset     = BinaryStream::swap_endian(cd->ident_offset);
  cd->nb_special_slots = BinaryStream::swap_endian(cd->nb_special_slots);
  cd->nb_code_slots    = BinaryStream::swap_endian(cd->nb_code_slots);
  cd->code_limit       = BinaryStream::swap_endian(cd->code_limit);
  cd->hash_size        = BinaryStream::swap_endian(cd->hash_size);
  cd->hash_type        = BinaryStream::swap_endian(cd->hash_type);
  cd->reserved         = BinaryStream::swap_endian(cd->reserved);
  cd->page_size        = BinaryStream::swap_endian(cd->page_size);
  cd->reserved2        = BinaryStream::swap_endian(cd->reserved2);
  cd->scatter_offset   = BinaryStream::swap_endian(cd->scatter_offset);
}


}
}
