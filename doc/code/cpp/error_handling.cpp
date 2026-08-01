#include <LIEF/PE.hpp>
#include <LIEF/errors.hpp>

using namespace LIEF;
using namespace LIEF::PE;

void error_handling() {
  // lief-doc: result-handling-start
  result<PE_TYPE> pe_type = PE::get_type("/tmp/NotPE.elf");
  if (pe_type) {
    PE_TYPE effective_type = pe_type.value();
  } else {
    lief_errors err = as_lief_err(pe_type);
  }
  // lief-doc: result-handling-end
}
