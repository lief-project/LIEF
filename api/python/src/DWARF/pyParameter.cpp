#include "LIEF/DWARF/Parameter.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types.hpp"
#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace nanobind::detail {
template<> struct type_hook<LIEF::dwarf::Parameter::Location> {
  static const std::type_info* get(const LIEF::dwarf::Parameter::Location *src) {
    using Parameter = LIEF::dwarf::Parameter;
    if (src) {
      if (Parameter::RegisterLoc::classof(src)) {
        return &typeid(Parameter::RegisterLoc);
      }
    }
    return &typeid(Parameter::Location);
  }
};
}

namespace LIEF::dwarf::py {
template<>
void create<dw::Parameter>(nb::module_& m) {
  nb::class_<dw::Parameter> param(m, "Parameter",
    R"doc(
    This class represents a DWARF parameter which can be either:
    - A regular function parameter (see: :class:`.parameters.Formal`)
    - A template type parameter (see: :class:`.parameters.TemplateType`)
    - A template value parameter (see: :class:`.parameters.TemplateValue`)
    )doc"_doc
  );

  using Location = dw::Parameter::Location;
  using RegisterLoc = dw::Parameter::RegisterLoc;

  nb::class_<Location> loc(param, "Location",
    R"doc(
    This class exposes information about the location of a parameter
    )doc"_doc);

  nb::enum_<dw::Parameter::Location::Type>(loc, "Type")
    .value("UNKNOWN", Location::Type::UNKNOWN)
    .value("REGISTER", Location::Type::REG);

  loc
    .def_ro("type", &Location::type);

  nb::class_<RegisterLoc, Location>(param, "RegisterLoc",
    R"doc(
    This class represents a register location
    )doc"_doc)

    .def_ro("id", &RegisterLoc::id, "DWARF id of the register"_doc);

  param
    .def_prop_ro("name", &dw::Parameter::name,
      R"doc(
      Name of the parameter
      )doc"_doc
    )

    .def_prop_ro("type", &dw::Parameter::type,
      R"doc(
      Type of this parameter
      )doc"_doc
    )

    .def_prop_ro("location", &dw::Parameter::location,
      R"doc(
      Location of this parameter. For instance it can be a specific register
      that is not following the calling convention.
      )doc"_doc
    )
  ;

  nb::module_ m_params = m.def_submodule("parameters");
  /* Formal */ {
    nb::class_<dw::parameters::Formal, dw::Parameter>(m_params, "Formal",
      R"doc(
      This class represents a regular function parameter.

      For instance, given this prototype:

      .. code-block:: cpp

        int main(int argc, const char** argv);

      The function ``main`` has two :class:`.Formal` parameters:

      1. ``argc`` (:attr:`lief.dwarf.Parameter.name`) typed as ``int``
          (:class:`~lief.dwarf.types.Base` from :attr:`lief.dwarf.Parameter.type`)
      2. ``argv`` (:attr:`lief.dwarf.Parameter.name`) typed as ``const char**``
          (:class:`~lief.dwarf.types.Const`)
      )doc"_doc
    )
      /* NOT NEEDED but dirty workaround to void stubgen generating this
       * kind of error:
       * lief/dwarf/parameters.pyi:1: error: Name "lief" is not defined  [name-defined]
       *
       * CAN BE REMOVED if one of these classes are API enhanced
       */
      .def_prop_ro("type", &dw::parameters::Formal::type)
    ;
  }

  /* TemplateValue */ {
    nb::class_<dw::parameters::TemplateValue, dw::Parameter>(m_params, "TemplateValue",
      R"doc(
      This class represents a template **value** parameter.

      For instance, given this prototype:

      .. code-block:: cpp

        template<int X = 5>
        void generic();

      The function ``generic`` has one :class:`.TemplateValue` parameter: ``X``
      )doc"_doc
    );
  }

  /* TemplateType */ {
    nb::class_<dw::parameters::TemplateType, dw::Parameter>(m_params, "TemplateType",
      R"doc(
      This class represents a template **type** parameter.

      For instance, given this prototype:

      .. code-block:: cpp

        template<class Y>
        void generic();

      The function ``generic`` has one :class:`.TemplateType` parameter: ``Y``
      )doc"_doc
    );
  }

}

}
