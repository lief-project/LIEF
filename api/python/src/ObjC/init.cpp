#include "ObjC/init.hpp"
#include "ObjC/pyObjC.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::objc {
class Metadata;
class Class;
class IVar;
class Property;
class Method;
class Protocol;
}

namespace LIEF::objc::py {
void init(nb::module_& m) {
  nb::module_ objc = m.def_submodule("objc");

  create<LIEF::objc::Metadata>(objc);
  create<LIEF::objc::Class>(objc);
  create<LIEF::objc::IVar>(objc);
  create<LIEF::objc::Protocol>(objc);
  create<LIEF::objc::Method>(objc);
  create<LIEF::objc::Property>(objc);
}
}
