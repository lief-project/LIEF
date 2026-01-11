/***
 * Copyright 2022 - 2026 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package lief.ghidra.core;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.LocalFileSystem;
import ghidra.util.Msg;
import lief.ghidra.util.exception.Exception;
import lief.macho.FatBinary;
import lief.macho.Header;

public class FSRLHelper {
    // See: Features/FileFormats/src/main/java/ghidra/file/formats/ubi/UniversalBinaryFileSystem.java
    public static final String UNIVERSAL_BINARY = "universalbinary";

    private static Map<String, Object> binaryCache = new HashMap<>();

    private static Object cache(String path, Object binary) {
        if (binary == null) {
            return null;
        }
        binaryCache.put(path, binary);
        return binary;
    }

    public static File getContainerPath(FSRL fsrl) throws Exception {
        FSRLRoot root = fsrl.getFS();
        if (root.getProtocol().equals(LocalFileSystem.FSTYPE)) {
            File file = new File(fsrl.getPath());
            if (!file.exists() || !file.isFile()) {
                throw new Exception(file.getPath() + " does not exist");
            }
            return file;
        }

        FSRL container = root.getContainer();

        if (container == null) {
            throw new Exception("Expecting a non null container");
        }

        return getContainerPath(container);
    }

    static boolean isEquivalent(Header.CpuType type, int subtype, String[] names) {
        String processorName = names[0].toLowerCase();
        String bitsize = names[1].toLowerCase();
        String cpusubtype = names[2].toLowerCase().substring(/*len(cpu0x)*/5);
        Msg.debug(FSRLHelper.class, String.format(
            "Processor Name %s, bitsize: %s, cpusubtype: %s",
            processorName, bitsize, cpusubtype
        ));

        Msg.debug(FSRLHelper.class, String.format(
            "Type %s, subtype: %s",
            type.toString(), Integer.toHexString(subtype)
        ));
        switch (processorName) {
            case "x86": {
                if (bitsize.equals("32")) {
                    return type == Header.CpuType.X86;
                }

                if (bitsize.equals("64")) {
                    return type == Header.CpuType.X86_64;
                }
                return false;
            }

            case "aarch64": {
                if (type != Header.CpuType.ARM64) {
                    return false;
                }

                if (cpusubtype.equals(Integer.toHexString(subtype))) {
                    return true;
                }

                return false;
            }

            case "arm": {
                return type == Header.CpuType.ARM;
            }
        }
        return false;
    }

    public static Object load(FSRL fsrl) throws Exception {
        File container = getContainerPath(fsrl);
        String protocol = fsrl.getFS().getProtocol();
        String path = container.getPath();

        if (binaryCache.containsKey(path)) {
            return binaryCache.get(path);
        }

        switch (protocol) {
            case LocalFileSystem.FSTYPE: {
                if (lief.pe.Utils.isPE(path)) {
                    return cache(path, lief.pe.Binary.parse(path));
                }
                else if (lief.elf.Utils.isELF(path)) {
                    return cache(path, lief.elf.Binary.parse(path));
                }
                else if (lief.macho.Utils.isMachO(path)) {
                    return cache(path, lief.macho.Binary.parse(path));
                }

                throw new Exception(String.format(
                    "DWARF exporter requires an ELF, PE or Mach-O (%s)", path
                ));
            }

            case UNIVERSAL_BINARY: {
                // In the case of a FAT binary, fsrl.getName() is defined
                // as follows: <processor> - <bitSize> - cpu0x<cpusubtype>
                // For instance:
                //  - AARCH64-64-cpu0x80000002
                //  - X86-64-cpu0x3
                //
                // Reference:
                // Ghidra/Features/FileFormats/[...]/UniversalBinaryFileSystem.java
                //  -> open(TaskMonitor monitor)
                String name = fsrl.getName();
                String[] chunks = name.split("-");
                if (chunks.length != 3 || !chunks[2].startsWith("cpu0x")) {
                    throw new Exception(String.format(
                        "Unsupported universal binary name: '%s'",
                        name
                    ));
                }
                FatBinary fat = lief.macho.FatBinary.parse(path);
                if (fat == null) {
                    throw new Exception(String.format(
                        "Can't parse %s with LIEF", path
                    ));
                }

                for (lief.macho.Binary fit : fat) {
                    Header header = fit.getHeader();
                    Header.CpuType cputype = header.getCpuType();
                    int subtype = header.getCpuSubType();

                    if (isEquivalent(cputype, subtype, chunks)) {
                        return cache(path, fit);
                    }
                }

                throw new Exception(String.format(
                    "Could not find '%s' in '%s' with LIEF. Please open an issue",
                    name, path
                ));
            }
        }
        throw new Exception(String.format(
            "Protocol '%s' is not supported by LIEF", protocol
        ));
    }
}
