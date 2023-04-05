#include "LIEF/PE/Exception.hpp"


namespace LIEF {
namespace PE {
namespace details {

}


Exception::Exception(uint64_t address, uint64_t end) :
  Function{address }
{
  size(end - address);
}
}}


