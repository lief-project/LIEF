#include "LIEF/BinaryStream/Convert.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"

/* In place conversions for BinaryStream/VectorStream data */

namespace LIEF {
namespace Convert {

template<typename T>
void swap_endian(T *v) {
  static_assert(std::is_integral<T>::value, "Only integer types can use generic endian swap");
  *v = BinaryStream::swap_endian(*v);
}

/*
 * Force instantiation of template for types used
 */
template void swap_endian<uint16_t>(uint16_t *v);
template void swap_endian<uint32_t>(uint32_t *v);
template void swap_endian<uint64_t>(uint64_t *v);
template void swap_endian<char16_t>(char16_t *v);

}
}
