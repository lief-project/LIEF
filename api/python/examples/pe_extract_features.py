#!/usr/bin/env python
"""Extract PE binary features for analysis and machine learning.

Extracts structural features from PE files suitable for malware detection,
binary classification, or general analysis. Outputs a JSON report of the
binary's characteristics.

Example:

    $ python pe_extract_features.py malware.exe
    {
      "filename": "malware.exe",
      "header": { ... },
      "sections": [ ... ],
      "imports": { ... },
      "exports": { ... },
      "rich_header": { ... },
      ...
    }

    $ python pe_extract_features.py --summary program.exe
    Feature Summary: program.exe
    ================================================
      File Size:            102400 bytes
      Sections:             5
      Imports:              3 libraries, 47 functions
      ...
"""

import argparse
import json
import math
import sys
from collections import Counter

import lief


def compute_entropy(data):
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_header_features(binary):
    """Extract PE header features."""
    hdr = binary.header
    opt = binary.optional_header

    return {
        "machine": str(hdr.machine),
        "number_of_sections": hdr.numberof_sections,
        "timestamp": hdr.time_date_stamps,
        "characteristics": [str(c) for c in hdr.characteristics_list],
        "magic": str(opt.magic),
        "major_linker_version": opt.major_linker_version,
        "minor_linker_version": opt.minor_linker_version,
        "sizeof_code": opt.sizeof_code,
        "sizeof_initialized_data": opt.sizeof_initialized_data,
        "sizeof_uninitialized_data": opt.sizeof_uninitialized_data,
        "entrypoint": opt.addressof_entrypoint,
        "imagebase": opt.imagebase,
        "section_alignment": opt.section_alignment,
        "file_alignment": opt.file_alignment,
        "sizeof_image": opt.sizeof_image,
        "sizeof_headers": opt.sizeof_headers,
        "dll_characteristics": [str(c) for c in opt.dll_characteristics_list],
        "subsystem": str(opt.subsystem),
    }


def extract_section_features(binary):
    """Extract features for each PE section."""
    sections = []
    for section in binary.sections:
        raw = bytes(section.content)
        sections.append(
            {
                "name": section.name,
                "virtual_size": section.virtual_size,
                "virtual_address": section.virtual_address,
                "sizeof_raw_data": section.size,
                "entropy": compute_entropy(raw),
                "characteristics": [str(c) for c in section.characteristics_lists],
            }
        )
    return sections


def extract_import_features(binary):
    """Extract import table features."""
    imports = {}
    total_functions = 0

    for imp in binary.imports:
        functions = [
            entry.name if not entry.is_ordinal else f"ord({entry.ordinal})"
            for entry in imp.entries
        ]
        imports[imp.name] = functions
        total_functions += len(functions)

    return {
        "libraries": list(imports.keys()),
        "library_count": len(imports),
        "function_count": total_functions,
        "details": imports,
    }


def extract_export_features(binary):
    """Extract export table features."""
    export = binary.get_export()
    if export is None:
        return {"name": None, "count": 0, "entries": []}

    entries = []
    for entry in export.entries:
        e = {"name": entry.name, "ordinal": entry.ordinal}
        if entry.is_forwarded:
            fwd = entry.forward_information
            e["forwarded_to"] = f"{fwd.library}.{fwd.function}"
        entries.append(e)

    return {
        "name": export.name,
        "count": len(entries),
        "entries": entries,
    }


def extract_rich_header_features(binary):
    """Extract Rich header features (compiler toolchain info)."""
    if binary.rich_header is None:
        return None

    entries = []
    for entry in binary.rich_header.entries:
        entries.append(
            {
                "build_id": entry.build_id,
                "count": entry.count,
                "id": entry.id,
            }
        )

    return {
        "entries": entries,
        "key": binary.rich_header.key,
    }


def extract_signature_features(binary):
    """Extract Authenticode signature info."""
    if not binary.signatures:
        return {"signed": False}

    sigs = []
    for sig in binary.signatures:
        certs = []
        for cert in sig.certificates:
            certs.append(
                {
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "serial_number": cert.serial_number.hex(),
                    "valid_from": str(cert.valid_from),
                    "valid_to": str(cert.valid_to),
                }
            )
        sigs.append(
            {
                "version": sig.version,
                "digest_algorithm": str(sig.digest_algorithm),
                "certificates": certs,
            }
        )

    result = binary.verify_signature()
    return {
        "signed": True,
        "valid": result == lief.PE.Signature.VERIFICATION_FLAGS.OK,
        "verification": str(result),
        "signatures": sigs,
    }


def extract_all_features(filename):
    """Extract all features from a PE binary."""
    binary = lief.PE.parse(filename)
    if binary is None:
        return None

    return {
        "filename": filename,
        "header": extract_header_features(binary),
        "sections": extract_section_features(binary),
        "imports": extract_import_features(binary),
        "exports": extract_export_features(binary),
        "rich_header": extract_rich_header_features(binary),
        "signature": extract_signature_features(binary),
    }


def print_summary(features):
    """Print a human-readable summary of extracted features."""
    print(f"Feature Summary: {features['filename']}")
    print("=" * 48)

    hdr = features["header"]
    print(f"  {'Machine:':<28} {hdr['machine']}")
    print(f"  {'Subsystem:':<28} {hdr['subsystem']}")
    print(f"  {'Entrypoint:':<28} 0x{hdr['entrypoint']:x}")
    print(f"  {'Image Size:':<28} {hdr['sizeof_image']} bytes")
    print()

    sections = features["sections"]
    print(f"  Sections ({len(sections)}):")
    for sec in sections:
        flag = ""
        if sec["entropy"] > 7.0:
            flag = " [HIGH ENTROPY]"
        elif sec["entropy"] < 0.5 and sec["sizeof_raw_data"] > 0:
            flag = " [LOW ENTROPY]"
        print(
            f"    {sec['name']:<12} size={sec['sizeof_raw_data']:<8} entropy={sec['entropy']:.2f}{flag}"
        )
    print()

    imp = features["imports"]
    print(
        f"  Imports: {imp['library_count']} libraries, {imp['function_count']} functions"
    )
    for lib in imp["libraries"]:
        print(f"    {lib} ({len(imp['details'][lib])} functions)")
    print()

    exp = features["exports"]
    if exp["count"] > 0:
        print(f"  Exports: {exp['count']} functions (DLL name: {exp['name']})")
        print()

    sig = features["signature"]
    print(f"  Signed: {'Yes' if sig['signed'] else 'No'}")
    if sig["signed"]:
        print(f"  Signature Valid: {'Yes' if sig['valid'] else 'No'}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Extract PE binary features for analysis"
    )
    parser.add_argument("binaries", nargs="+", help="PE binaries to analyze")
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print human-readable summary instead of JSON",
    )
    parser.add_argument(
        "--indent", type=int, default=2, help="JSON indentation level (default: 2)"
    )
    args = parser.parse_args()

    for path in args.binaries:
        features = extract_all_features(path)
        if features is None:
            print(f"Error: failed to parse '{path}' as PE", file=sys.stderr)
            continue

        if args.summary:
            print_summary(features)
        else:
            print(json.dumps(features, indent=args.indent))


if __name__ == "__main__":
    main()
