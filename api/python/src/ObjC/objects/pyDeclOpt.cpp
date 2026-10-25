#include "LIEF/ObjC/DeclOpt.hpp"
#include "ObjC/pyObjC.hpp"

namespace LIEF::objc::py {
template<>
void create<DeclOpt>(nb::module_& m) {
  nb::class_<DeclOpt>(m, "DeclOpt",
                      R"doc(
                      This structure wraps options to tweak the generated output of
                      functions like :func:`lief.objc.Metadata.to_decl`
                      )doc"_doc)
      .def(nb::init<>())
      .def_rw("show_annotations", &DeclOpt::show_annotations,
              "Whether annotations like method's address should be printed."_doc);
}

}
