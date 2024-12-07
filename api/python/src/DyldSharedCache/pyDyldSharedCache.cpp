#include "LIEF/DyldSharedCache/DyldSharedCache.hpp"
#include "DyldSharedCache/pyDyldSharedCache.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

#include "nanobind/extra/random_access_iterator.hpp"
#include "nanobind/utils.hpp"

#include "typing.hpp"
#include "pyutils.hpp"
#include "pyErr.hpp"

struct PathLike : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(PathLike, nanobind::object);

  NB_OBJECT_DEFAULT(PathLike, object, "os.PathLike", check)

  static bool check(handle h) {
    return true;
  }
};


namespace LIEF::dsc::py {
template<>
void create<dsc::DyldSharedCache>(nb::module_& m) {
  nb::class_<dsc::DyldSharedCache> cache(m, "DyldSharedCache",
    R"doc(
    This class represents a dyld shared cache file.
    )doc"_doc
  );

  nb::enum_<dsc::DyldSharedCache::VERSION>(cache, "VERSION")
    .value("UNKNOWN", dsc::DyldSharedCache::VERSION::UNKNOWN)
    .value("DYLD_95_3", dsc::DyldSharedCache::VERSION::DYLD_95_3,
           "dyld-95.3 (2007-10-30)"_doc)
    .value("DYLD_195_5", dsc::DyldSharedCache::VERSION::DYLD_195_5,
           "dyld-195.5 (2011-07-13)"_doc)
    .value("DYLD_239_3", dsc::DyldSharedCache::VERSION::DYLD_239_3,
           "dyld-239.3 (2013-10-29)"_doc)
    .value("DYLD_360_14", dsc::DyldSharedCache::VERSION::DYLD_360_14,
           "dyld-360.14 (2015-09-04)"_doc)
    .value("DYLD_421_1", dsc::DyldSharedCache::VERSION::DYLD_421_1,
           "dyld-421.1 (2016-09-22)"_doc)
    .value("DYLD_832_7_1", dsc::DyldSharedCache::VERSION::DYLD_832_7_1,
           "dyld-832.7.1 (2020-11-19)"_doc)
    .value("DYLD_940", dsc::DyldSharedCache::VERSION::DYLD_940,
           "dyld-940 (2021-02-09)"_doc)
    .value("DYLD_1042_1", dsc::DyldSharedCache::VERSION::DYLD_1042_1,
           "dyld-1042.1 (2022-10-19)"_doc)
    .value("UNRELEASED", dsc::DyldSharedCache::VERSION::UNRELEASED,
           R"doc(
           This value is used for versions of dyld not publicly released or
           not yet supported by LIEF.
           )doc"_doc)
  ;


  nb::enum_<dsc::DyldSharedCache::DYLD_TARGET_PLATFORM>(cache, "PLATFORM",
    R"doc(Platforms supported by the dyld shared cache)doc"_doc
  )
    .value("UNKNOWN", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::UNKNOWN)
    .value("MACOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::MACOS)
    .value("IOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::IOS)
    .value("TVOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::TVOS)
    .value("WATCHOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::WATCHOS)
    .value("BRIDGEOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::BRIDGEOS)
    .value("IOSMAC", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::IOSMAC)
    .value("IOS_SIMULATOR", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::IOS_SIMULATOR)
    .value("TVOS_SIMULATOR", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::TVOS_SIMULATOR)
    .value("WATCHOS_SIMULATOR", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::WATCHOS_SIMULATOR)
    .value("DRIVERKIT", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::DRIVERKIT)
    .value("VISIONOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::VISIONOS)
    .value("VISIONOS_SIMULATOR", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::VISIONOS_SIMULATOR)
    .value("FIRMWARE", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::FIRMWARE)
    .value("SEPOS", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::SEPOS)
    .value("ANY", dsc::DyldSharedCache::DYLD_TARGET_PLATFORM::ANY)
  ;

  nb::enum_<dsc::DyldSharedCache::DYLD_TARGET_ARCH>(cache, "ARCH",
    R"doc(Architecture supported by the dyld shared cache)doc"_doc
  )
    .value("UNKNOWN", dsc::DyldSharedCache::DYLD_TARGET_ARCH::UNKNOWN)
    .value("I386", dsc::DyldSharedCache::DYLD_TARGET_ARCH::I386)
    .value("X86_64", dsc::DyldSharedCache::DYLD_TARGET_ARCH::X86_64)
    .value("X86_64H", dsc::DyldSharedCache::DYLD_TARGET_ARCH::X86_64H)
    .value("ARMV5", dsc::DyldSharedCache::DYLD_TARGET_ARCH::ARMV5)
    .value("ARMV6", dsc::DyldSharedCache::DYLD_TARGET_ARCH::ARMV6)
    .value("ARMV7", dsc::DyldSharedCache::DYLD_TARGET_ARCH::ARMV7)
    .value("ARM64", dsc::DyldSharedCache::DYLD_TARGET_ARCH::ARM64)
    .value("ARM64E", dsc::DyldSharedCache::DYLD_TARGET_ARCH::ARM64E)
  ;

  cache
    .def_static("from_path", &dsc::DyldSharedCache::from_path,
      R"doc(
      See: :meth:`lief.dsc.load` for the details
      )doc"_doc, "path"_a, "arch"_a = ""
    )
    .def_static("from_files", &dsc::DyldSharedCache::from_files,
      R"doc(
      See: :meth:`lief.dsc.load` for the details
      )doc"_doc, "files"_a
    )
    .def_prop_ro("filename", &dsc::DyldSharedCache::filename,
      R"doc(
      Filename of the dyld shared file associated with this object.

      For instance: ``dyld_shared_cache_arm64e, dyld_shared_cache_arm64e.62.dyldlinkedit``
      )doc"_doc
    )
    .def_prop_ro("version", &dsc::DyldSharedCache::version,
      R"doc(
      Version of dyld used by this cache
      )doc"_doc
    )
    .def_prop_ro("filepath", &dsc::DyldSharedCache::filepath,
      R"doc(
      Full path to the original dyld shared cache file associated with object
      (e.g. ``/cache/visionos/dyld_shared_cache_arm64e.42``)
      )doc"_doc
    )
    .def_prop_ro("load_address", &dsc::DyldSharedCache::load_address,
      R"doc(Based address of this cache)doc"_doc
    )
    .def_prop_ro("arch_name", &dsc::DyldSharedCache::arch_name,
      R"doc(Name of the architecture targeted by this cache (``x86_64h``))doc"_doc
    )
    .def_prop_ro("platform", &dsc::DyldSharedCache::platform,
      R"doc(Platform targeted by this cache (e.g. vision-os))doc"_doc
    )
    .def_prop_ro("arch", &dsc::DyldSharedCache::arch,
      R"doc(Architecture targeted by this cache)doc"_doc
    )
    .def_prop_ro("has_subcaches", &dsc::DyldSharedCache::has_subcaches,
      R"doc(True if the subcaches are associated with this cache)doc"_doc
    )
    .def("find_lib_from_va", &dsc::DyldSharedCache::find_lib_from_va,
        R"doc(
        Find the :class:`lief.dsc.Dylib` that encompasses the given virtual address.
        It returns ``None`` if a Dylib can't be found.
        )doc", "virtual_address"_a,
        nb::keep_alive<0, 1>()
    )
    .def("find_lib_from_path", &dsc::DyldSharedCache::find_lib_from_path,
        R"doc(
        Find the Dylib whose :attr:`lief.dsc.Dylib.path` matches the provided path.
        )doc", "path"_a,
        nb::keep_alive<0, 1>()
    )
    .def("find_lib_from_name", &dsc::DyldSharedCache::find_lib_from_name,
        R"doc(
        Find the Dylib whose filename of :attr:`lief.dsc.Dylib.path` matches the
        provided name.

        If multiple libraries have the same name (but with a different path),
        the **first one** matching the provided name is returned.
        )doc", "name"_a,
        nb::keep_alive<0, 1>()
    )
    .def_prop_ro("libraries",
        [] (const DyldSharedCache& self) {
          auto libraries = self.libraries();
          return nb::make_random_access_iterator(nb::type<DyldSharedCache>(), "dylib_iterator", libraries);
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Return a list-like of the :class:`~.Dylib` embedded in this dyld shared cache
        )doc"_doc
    )

    .def_prop_ro("mapping_info",
        [] (const DyldSharedCache& self) {
          auto mapping = self.mapping_info();
          return nb::make_random_access_iterator(nb::type<DyldSharedCache>(), "mapping_info_iterator", mapping);
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Return a list-like of the :class:`~.MappingInfo` embedded in this dyld shared cache
        )doc"_doc
    )

    .def_prop_ro("subcaches",
        [] (const DyldSharedCache& self) {
          auto subcaches = self.subcaches();
          return nb::make_random_access_iterator(nb::type<DyldSharedCache>(), "subcache_iterator", subcaches);
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Return a list-like of :class:`~.SubCache` embedded in this (main)
        dyld shared cache
        )doc"_doc
    )

    .def("get_content_from_va",
        [] (const DyldSharedCache& self, uint64_t addr, size_t size) {
          return nb::to_bytes(self.get_content_from_va(addr, size));
        },
        R"doc(
        Return the content at the specified virtual address
        )doc"_doc, "addr"_a, "size"_a
    )

    .def("cache_for_address", &DyldSharedCache::cache_for_address,
        R"doc(
        Find the sub-DyldSharedCache that wraps the given virtual address
        )doc"_doc, "address"_a, nb::keep_alive<0, 1>()
    )

    .def_prop_ro("main_cache", &DyldSharedCache::main_cache,
        R"doc(
        Return the principal dyld shared cache in the case of multiple subcaches
        )doc"_doc, nb::keep_alive<1, 0>()
    )

    .def("find_subcache", &DyldSharedCache::find_subcache,
        R"doc(
        Try to find the DyldSharedCache associated with the filename given
        in the first parameter.
        )doc"_doc, "filename"_a, nb::keep_alive<1, 0>()
    )

    .def("va_to_offset", [] (DyldSharedCache& self, uint64_t va) {
          return LIEF::py::error_or(&DyldSharedCache::va_to_offset, self, va);
        },
        R"doc(
        Convert the given virtual address into an offset.

        .. warning::

            If the shared cache contains multiple subcaches,
            this function needs to be called on the targeted subcache.
            See :func:`~.DyldSharedCache.cache_for_address` to find the
            associated subcache.
        )doc"_doc, "virtual_address"_a
    )

    .def("disassemble",
        [] (const DyldSharedCache& self, uint64_t addr) {
          auto insts = self.disassemble(addr);
          return nb::make_iterator<nb::rv_policy::reference_internal>(
            nb::type<DyldSharedCache>(), "instructions_iterator", insts
          );
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Disassemble instructions at the provided virtual address.

        This function returns an iterator over :class:`lief.assembly.Instruction`.
        )doc"_doc
    )

    .def("enable_caching", &DyldSharedCache::enable_caching,
        R"doc(
        When enabled, this function allows to record and to keep in *cache*,
        dyld shared cache information that are costly to access.

        For instance, GOT symbols, rebases information, stub symbols, ...

        It is **highly** recommended to enable this function when processing
        a dyld shared cache several times or when extracting a large number of
        :class:`lief.dsc.Dylib` with enhanced extraction options
        (e.g. :attr:`lief.dsc.Dylib.extract_opt_t.fix_branches`)

        One can enable caching by calling this function:

        .. code-block:: python

          dyld_cache = lief.dsc.load("macos-15.0.1/");
          dyld_cache.enable_caching("~/.cache/lief-dsc");

        One can also enable this cache optimization **globally** using the
        function: :func:`lief.dsc.enable_cache` or by setting the environment variable
        ``DYLDSC_ENABLE_CACHE`` to 1.
        )doc"_doc, "target_dir"_a
    )

    .def("flush_cache", &DyldSharedCache::flush_cache,
        R"doc(
        Flush internal information into the on-disk cache (see: :meth:`~.enable_caching`)
        )doc"_doc
    )
  ;

  m.def("load", nb::overload_cast<const std::vector<std::string>&>(&dsc::load),
        R"doc(
        Load a shared cache from a list of files.

        .. code-block:: cpp

          files = [
            "/tmp/dsc/dyld_shared_cache_arm64e",
            "/tmp/dsc/dyld_shared_cache_arm64e.1"
          ]
          cache = lief.dsc.load(files);
        )doc"_doc, "files"_a);

  m.def("load", [] (PathLike path, const std::string& arch) -> std::unique_ptr<DyldSharedCache> {
          if (auto path_str = LIEF::py::path_to_str(path)) {
            return load(*path_str, arch);
          }
          return nullptr;
        },
        R"doc(
        Load a shared cache from the a single file or from a directory specified
        by the ``path`` parameter.

        In the case where multiple architectures are
        available in the ``path`` directory, the ``arch`` parameter can be used to
        define which architecture should be prefered.

        **Example:**

        .. code-block:: python

          // From a directory (split caches)
          cache = lief.dsc.load("vision-pro-2.0/");

          // From a single cache file
          cache = lief.dsc.load("ios-14.2/dyld_shared_cache_arm64");

          // From a directory with multiple architectures
          cache = lief.dsc.load("macos-12.6/", "x86_64h");
        )doc"_doc, "path"_a, "arch"_a = "");
}
}
