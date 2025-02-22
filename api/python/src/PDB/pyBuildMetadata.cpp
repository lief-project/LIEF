#include <sstream>
#include "LIEF/PDB/BuildMetadata.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

#include <nanobind/extra/stl/lief_optional.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::BuildMetadata>(nb::module_& m) {
  nb::class_<pdb::BuildMetadata> obj(m, "BuildMetadata",
    R"doc(
    This class wraps build metadata represented by the codeview symbols:
    ``S_COMPILE3, S_COMPILE2, S_BUILDINFO``
    )doc"_doc
  );

  using LANG = pdb::BuildMetadata::LANG;
  nb::enum_<LANG>(obj, "LANG")
    .value("C", LANG::C)
    .value("CPP", LANG::CPP)
    .value("FORTRAN", LANG::FORTRAN)
    .value("MASM", LANG::MASM)
    .value("PASCAL_LANG", LANG::PASCAL_LANG)
    .value("BASIC", LANG::BASIC)
    .value("COBOL", LANG::COBOL)
    .value("LINK", LANG::LINK)
    .value("CVTRES", LANG::CVTRES)
    .value("CVTPGD", LANG::CVTPGD)
    .value("CSHARP", LANG::CSHARP)
    .value("VB", LANG::VB)
    .value("ILASM", LANG::ILASM)
    .value("JAVA", LANG::JAVA)
    .value("JSCRIPT", LANG::JSCRIPT)
    .value("MSIL", LANG::MSIL)
    .value("HLSL", LANG::HLSL)
    .value("OBJC", LANG::OBJC)
    .value("OBJCPP", LANG::OBJCPP)
    .value("SWIFT", LANG::SWIFT)
    .value("ALIASOBJ", LANG::ALIASOBJ)
    .value("RUST", LANG::RUST)
    .value("GO", LANG::GO)
    .value("UNKNOWN", LANG::UNKNOWN);

  using CPU = pdb::BuildMetadata::CPU;
  nb::enum_<CPU>(obj, "CPU")
    .value("INTEL_8080", CPU::INTEL_8080)
    .value("INTEL_8086", CPU::INTEL_8086)
    .value("INTEL_80286", CPU::INTEL_80286)
    .value("INTEL_80386", CPU::INTEL_80386)
    .value("INTEL_80486", CPU::INTEL_80486)
    .value("PENTIUM", CPU::PENTIUM)
    .value("PENTIUMPRO", CPU::PENTIUMPRO)
    .value("PENTIUM3", CPU::PENTIUM3)
    .value("MIPS", CPU::MIPS)
    .value("MIPS16", CPU::MIPS16)
    .value("MIPS32", CPU::MIPS32)
    .value("MIPS64", CPU::MIPS64)
    .value("MIPSI", CPU::MIPSI)
    .value("MIPSII", CPU::MIPSII)
    .value("MIPSIII", CPU::MIPSIII)
    .value("MIPSIV", CPU::MIPSIV)
    .value("MIPSV", CPU::MIPSV)
    .value("M68000", CPU::M68000)
    .value("M68010", CPU::M68010)
    .value("M68020", CPU::M68020)
    .value("M68030", CPU::M68030)
    .value("M68040", CPU::M68040)
    .value("ALPHA", CPU::ALPHA)
    .value("ALPHA_21164", CPU::ALPHA_21164)
    .value("ALPHA_21164A", CPU::ALPHA_21164A)
    .value("ALPHA_21264", CPU::ALPHA_21264)
    .value("ALPHA_21364", CPU::ALPHA_21364)
    .value("PPC601", CPU::PPC601)
    .value("PPC603", CPU::PPC603)
    .value("PPC604", CPU::PPC604)
    .value("PPC620", CPU::PPC620)
    .value("PPCFP", CPU::PPCFP)
    .value("PPCBE", CPU::PPCBE)
    .value("SH3", CPU::SH3)
    .value("SH3E", CPU::SH3E)
    .value("SH3DSP", CPU::SH3DSP)
    .value("SH4", CPU::SH4)
    .value("SHMEDIA", CPU::SHMEDIA)
    .value("ARM3", CPU::ARM3)
    .value("ARM4", CPU::ARM4)
    .value("ARM4T", CPU::ARM4T)
    .value("ARM5", CPU::ARM5)
    .value("ARM5T", CPU::ARM5T)
    .value("ARM6", CPU::ARM6)
    .value("ARM_XMAC", CPU::ARM_XMAC)
    .value("ARM_WMMX", CPU::ARM_WMMX)
    .value("ARM7", CPU::ARM7)
    .value("OMNI", CPU::OMNI)
    .value("IA64", CPU::IA64)
    .value("IA64_2", CPU::IA64_2)
    .value("CEE", CPU::CEE)
    .value("AM33", CPU::AM33)
    .value("M32R", CPU::M32R)
    .value("TRICORE", CPU::TRICORE)
    .value("X64", CPU::X64)
    .value("EBC", CPU::EBC)
    .value("THUMB", CPU::THUMB)
    .value("ARMNT", CPU::ARMNT)
    .value("ARM64", CPU::ARM64)
    .value("HYBRID_X86ARM64", CPU::HYBRID_X86ARM64)
    .value("ARM64EC", CPU::ARM64EC)
    .value("ARM64X", CPU::ARM64X)
    .value("D3D11_SHADER", CPU::D3D11_SHADER)
    .value("UNKNOWN", CPU::UNKNOWN);

  using version_t = BuildMetadata::version_t;
  nb::class_<version_t>(obj, "version_t",
    "This structure represents a version for the backend or the frontend"_doc
  )
    .def_rw("major", &version_t::major, "Major version"_doc)
    .def_rw("minor", &version_t::minor, "Minor version"_doc)
    .def_rw("build", &version_t::build, "Build version"_doc)
    .def_rw("qfe", &version_t::qfe, "Quick Fix Engineeringa version"_doc);


  using build_info_t = BuildMetadata::build_info_t;
  nb::class_<build_info_t>(obj, "build_info_t",
    "Build information represented by the ``S_BUILDINFO`` symbol"_doc
  )
    .def_rw("cwd", &build_info_t::cwd,
            "Working directory where the *build tool* was invoked"_doc)
    .def_rw("build_tool", &build_info_t::build_tool,
            R"doc(Path to the build tool (e.g. ``C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.36.32532\bin\HostX64\x64\CL.exe``)doc"_doc)
    .def_rw("source_file", &build_info_t::source_file,
            "Source file consumed by the *build tool*"_doc)
    .def_rw("pdb", &build_info_t::pdb,
            "PDB path"_doc)
    .def_rw("command_line", &build_info_t::command_line,
            "Command line arguments used to invoke the *build tool*"_doc);

  obj
    .def_prop_ro("frontend_version", &BuildMetadata::frontend_version,
      "Version of the frontend (e.g. ``19.36.32537``)"_doc
    )

    .def_prop_ro("backend_version", &BuildMetadata::backend_version,
      "Version of the backend (e.g. ``14.36.32537``)"_doc
    )

    .def_prop_ro("version", &BuildMetadata::version,
      R"doc(
      Version of the *tool* as a string. For instance, ``Microsoft (R) CVTRES``,
      ``Microsoft (R) LINK``.
      )doc"_doc
    )

    .def_prop_ro("language", &BuildMetadata::language,
      "Source language"_doc
    )

    .def_prop_ro("target_cpu", &BuildMetadata::target_cpu,
      "Target CPU"_doc
    )

    .def_prop_ro("build_info", &BuildMetadata::build_info,
      "Build information represented by the ``S_BUILDINFO`` symbol"_doc
    )

    .def_prop_ro("env", &BuildMetadata::env,
      "Environment information represented by the ``S_ENVBLOCK`` symbol"_doc
    )

    LIEF_DEFAULT_STR(pdb::BuildMetadata);
}

}
