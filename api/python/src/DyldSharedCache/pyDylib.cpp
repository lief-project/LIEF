#include "LIEF/DyldSharedCache/Dylib.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "DyldSharedCache/pyDyldSharedCache.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>


namespace LIEF::dsc::py {
template<>
void create<dsc::Dylib>(nb::module_& m) {
  nb::class_<dsc::Dylib> obj(m, "Dylib",
    R"doc(
    This class represents a library embedded in a dyld shared cache.
    It mirrors the original ``dyld_cache_image_info`` structure.
    )doc"_doc
  );

  nb::class_<Dylib::extract_opt_t>(obj, "extract_opt_t",
    R"doc(
    This structure is used to tweak the extraction process while calling
    :meth:`lief.dsc.Dylib.get`. These options allow to deoptimize the dylib and
    get an accurate representation of the origin Mach-O binary.
    )doc"
  )
    .def(nb::init<>())
    .def_rw("pack", &Dylib::extract_opt_t::pack,
      R"doc(
      Whether the segment's offsets should be packed to avoid
      an in-memory size while writing back the binary.

      .. note::

          This option does not have an impact on the performances
      )doc"_doc
    )

    .def_rw("fix_branches", &Dylib::extract_opt_t::fix_branches,
      R"doc(
      Fix call instructions that target addresses outside the current dylib
      virtual space.

      .. warning::

        Enabling this option can have a significant impact on the
        performances. Make sure to enable the internal cache mechanism:
        :func:`lief.dsc.enable_cache` or :meth:`lief.dsc.DyldSharedCache.enable_caching`
      )doc"_doc
    )

    .def_rw("fix_memory", &Dylib::extract_opt_t::fix_memory,
      R"doc(
      Fix memory accesses performed outside the dylib's virtual space

      .. warning::

        Enabling this option can have a significant impact on the
        performances. Make sure to enable the internal cache mechanism:
        :func:`lief.dsc.enable_cache` or :meth:`lief.dsc.DyldSharedCache.enable_caching`
      )doc"_doc
    )

    .def_rw("fix_relocations", &Dylib::extract_opt_t::fix_relocations,
      R"doc(
      Recover and fix relocations

      .. warning::

        Enabling this option can have a significant impact on the
        performances. Make sure to enable the internal cache mechanism:
        :func:`lief.dsc.enable_cache` or :meth:`lief.dsc.DyldSharedCache.enable_caching`
      )doc"_doc
    )

    .def_rw("fix_objc", &Dylib::extract_opt_t::fix_relocations,
      R"doc(
      Fix Objective-C information

      .. warning::

        Enabling this option can have a significant impact on the
        performances. Make sure to enable the internal cache mechanism:
        :func:`lief.dsc.enable_cache` or :meth:`lief.dsc.DyldSharedCache.enable_caching`
      )doc"_doc
    )

    .def_prop_rw("create_dyld_chained_fixup_cmd",
      [] (const Dylib::extract_opt_t& opt) -> bool {
        return opt.create_dyld_chained_fixup_cmd.value_or(false);
      },
      [] (Dylib::extract_opt_t& self, bool value) {
        self.create_dyld_chained_fixup_cmd = value;
      },
      R"doc(
      Whether the ``LC_DYLD_CHAINED_FIXUPS`` command should be (re)created.

      If this value is not set, LIEF will add the command only if it's
      meaningful regarding the other options
      )doc"_doc
    )
  ;

  obj
    .def_prop_ro("path", &dsc::Dylib::path,
      R"doc(Original path of the library (e.g. ``/usr/lib/libcryptex.dylib``))doc"_doc
    )
    .def_prop_ro("address", &dsc::Dylib::address,
      R"doc(In-memory address of the library)doc"_doc
    )
    .def_prop_ro("modtime", &dsc::Dylib::modtime,
      R"doc(
      Modification time of the library matching ``stat.st_mtime``, or 0
      )doc"_doc
    )
    .def_prop_ro("inode", &dsc::Dylib::inode,
      R"doc(
      File serial number matching ``stat.st_ino`` or 0

      Note that for shared cache targeting iOS, this value can hold a hash of
      the path (if modtime is set to 0)
      )doc"_doc
    )
    .def_prop_ro("padding", &dsc::Dylib::padding,
      R"doc(Padding alignment value (should be 0))doc"_doc
    )

    .def("get", &dsc::Dylib::get,
      R"doc(
      Get a :class:`lief.MachO.Binary` representation for this Dylib.

      One can use this function to write back the Mach-O binary on the disk:

      .. code-block:: cpp

         dyld_cache: lief.dsc.DyldSharedCache = ...
         dyld_cache.libraries[10].get().write("libsystem.dylib")

      )doc"_doc, "opt"_a = Dylib::extract_opt_t()
    )
  ;
}
}
