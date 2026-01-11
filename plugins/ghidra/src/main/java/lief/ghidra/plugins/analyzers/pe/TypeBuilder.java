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
package lief.ghidra.plugins.analyzers.pe;

import java.util.Optional;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.util.Msg;

import lief.ghidra.plugins.analyzers.Context;

public class TypeBuilder<T> extends lief.ghidra.plugins.analyzers.TypeBuilder<T> {
    public final static DataType ULONG = U32;

    public TypeBuilder(Context<T> context) {
        super(context);
    }

    public void addBitField(StructureDataType S, DataType baseDataType,
        int bitSize, String componentName, String comment)
    {
        try {
            S.addBitField(baseDataType, bitSize, componentName, comment);
        } catch (InvalidDataTypeException e) {
            Msg.error(TypeBuilder.class, e);
        }
    }

    @Override
    public Optional<DataType> getType(String name) {
        DataTypeManager typeManager = context
            .getProgram()
            .getDataTypeManager();

        switch (name) {
            case "IMAGE_LOAD_CONFIG_CODE_INTEGRITY": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_LOAD_CONFIG_CODE_INTEGRITY", 0);
                S.add(U16, "Flags",
                    "Flags to indicate if CI information is available, etc."
                );
                S.add(U16, "Catalog",
                    "0xFFFF means not available"
                );
                S.add(U32, "CatalogOffset",
                    "0xFFFF means not available"
                );
                S.add(U32, "Reserved",
                    "Additional bitmask to be defined later"
                );
                S.setCategoryPath(getCategoryPath());

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_LOAD_CONFIG_CODE_INTEGRITY", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_GUARD_FLAGS": {
                EnumDataType E =
                    new EnumDataType("IMAGE_GUARD_FLAGS", U32.getLength());

                E.add("IMAGE_GUARD_CF_INSTRUMENTED", 0x00000100,
                    "Module performs control flow integrity checks using system-supplied support"
                );

                E.add("IMAGE_GUARD_CFW_INSTRUMENTED", 0x00000200,
                    "Module performs control flow and write integrity checks"
                );

                E.add("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", 0x00000400,
                    "Module contains valid control flow target metadata"
                );

                E.add("IMAGE_GUARD_SECURITY_COOKIE_UNUSED", 0x00000800,
                    "Module does not make use of the /GS security cookie"
                );

                E.add("IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", 0x00001000,
                    "Module supports read only delay load IAT"
                );

                E.add("IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION", 0x00002000,
                    "Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected"
                );

                E.add("IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", 0x00004000,
                    "Module contains suppressed export information. This also infers that the address taken" +
                    "taken IAT table is also present in the load config"
                );

                E.add("IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION", 0x00008000,
                    "Module enables suppression of exports"
                );

                E.add("IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", 0x00010000,
                    "Module contains longjmp target information"
                );

                E.add("IMAGE_GUARD_RF_INSTRUMENTED", 0x00020000,
                    "Module contains return flow instrumentation and metadata"
                );

                E.add("IMAGE_GUARD_RF_ENABLE", 0x00040000,
                    "Module requests that the OS enable return flow protection"
                );

                E.add("IMAGE_GUARD_RETPOLINE_PRESENT", 0x00100000,
                    "Module was built with retpoline support"
                );

                E.add("IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT", 0x00400000,
                    "Module contains EH continuation target information"
                );

                E.add("IMAGE_GUARD_XFG_ENABLED", 0x00800000,
                    "Module was built with xfg (deprecated)"
                );

                E.add("IMAGE_GUARD_CASTGUARD_PRESENT", 0x01000000,
                    "Module has CastGuard instrumentation present"
                );

                E.add("IMAGE_GUARD_MEMCPY_PRESENT", 0x02000000,
                    "Module has Guarded Memcpy instrumentation present"
                );

                E.setCategoryPath(getCategoryPath());

                return Optional.of(
                    typeManager.addDataType(E, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64EC_METADATA": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_ARM64EC_METADATA", 0);
                S.add(ULONG, "Version", null);
                S.add(RVA,   "CodeMap", null);
                S.add(ULONG, "CodeMapCount", null);
                S.add(RVA,   "CodeRangesToEntryPoints", null);
                S.add(RVA,   "RedirectionMetadata", null);
                S.add(RVA,   "__os_arm64x_dispatch_call_no_redirect", null);
                S.add(RVA,   "__os_arm64x_dispatch_ret", null);
                S.add(RVA,   "__os_arm64x_dispatch_call", null);
                S.add(RVA,   "__os_arm64x_dispatch_icall", null);
                S.add(RVA,   "__os_arm64x_dispatch_icall_cfg", null);
                S.add(RVA,   "AlternateEntryPoint", null);
                S.add(RVA,   "AuxiliaryIAT", null);
                S.add(ULONG, "CodeRangesToEntryPointsCount", null);
                S.add(ULONG, "RedirectionMetadataCount", null);
                S.add(RVA,   "GetX64InformationFunctionPointer", null);
                S.add(RVA,   "SetX64InformationFunctionPointer", null);
                S.add(RVA,   "ExtraRFETable", null);
                S.add(ULONG, "ExtraRFETableSize", null);
                S.add(RVA,   "__os_arm64x_dispatch_fptr", null);
                S.add(RVA,   "AuxiliaryIATCopy", null);
                S.setCategoryPath(getCategoryPath());

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_ARM64EC_METADATA", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64EC_METADATA_V2": {
                DataType base = getType("IMAGE_ARM64EC_METADATA").get();
                StructureDataType S =
                    new StructureDataType("_IMAGE_ARM64EC_METADATA_V2", 0);
                S.add(base, "V1", null);

                S.add(RVA,   "AuxDelayloadIAT", null);
                S.add(RVA,   "AuxDelayloadIATCopy", null);
                S.add(ULONG, "ReservedBitField", null);

                S.setCategoryPath(getCategoryPath());

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_ARM64EC_METADATA_V2", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_CHPE_METADATA_X86": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_CHPE_METADATA_X86", 0);
                S.add(ULONG, "Version", null);
                S.add(RVA,   "CHPECodeAddressRangeOffset", null);
                S.add(ULONG, "CHPECodeAddressRangeCount", null);
                S.add(RVA,   "WowA64ExceptionHandlerFunctionPointer", null);
                S.add(RVA,   "WowA64DispatchCallFunctionPointer", null);
                S.add(RVA,   "WowA64DispatchIndirectCallFunctionPointer", null);
                S.add(RVA,   "WowA64DispatchIndirectCallCfgFunctionPointer", null);
                S.add(RVA,   "WowA64DispatchRetFunctionPointer", null);
                S.add(RVA,   "WowA64DispatchRetLeafFunctionPointer", null);
                S.add(RVA,   "WowA64DispatchJumpFunctionPointer", null);
                S.setCategoryPath(getCategoryPath());

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_CHPE_METADATA_X86", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_CHPE_METADATA_X86_V2": {
                DataType base = getType("IMAGE_CHPE_METADATA_X86").get();
                StructureDataType S =
                    new StructureDataType("_IMAGE_CHPE_METADATA_X86_V2", 0);
                S.add(base, "V1", null);

                S.add(RVA, "CompilerIATPointer", null);

                S.setCategoryPath(getCategoryPath());

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_CHPE_METADATA_X86_V2", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_CHPE_METADATA_X86_V3": {
                DataType base = getType("IMAGE_CHPE_METADATA_X86_V2").get();
                StructureDataType S =
                    new StructureDataType("_IMAGE_CHPE_METADATA_X86_V3", 0);
                S.add(base, "V2", null);

                S.add(RVA, "WowA64RdtscFunctionPointer", null);

                S.setCategoryPath(getCategoryPath());

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_CHPE_METADATA_X86_V3", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64EC_METADATA_CODE_RANGE_TYPE": {
                EnumDataType E =
                    new EnumDataType("IMAGE_ARM64EC_METADATA_CODE_RANGE_TYPE", U32.getLength());

                E.add("ARM64", 0, "Pure ARM64 code");
                E.add("ARM64EC", 1, "ARM64EC hybrid code (compatible with x64).");
                E.add("AMD64", 2, "x64 code");

                E.setCategoryPath(getCategoryPath());

                return Optional.of(
                    typeManager.addDataType(E, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64EC_METADATA_CODE_RANGE": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_ARM64EC_METADATA_CODE_RANGE", 0);

                S.setPackingEnabled(true);
                addBitField(S,
                    getType("IMAGE_ARM64EC_METADATA_CODE_RANGE_TYPE").get(),
                    2, "Type", null);

                addBitField(S, U32, 30, "RVA", null);
                S.add(U32, "Length", null);

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_ARM64EC_METADATA_CODE_RANGE", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT", 0);

                S.add(RVA, "StartRva", null);
                S.add(RVA, "EndRva", null);
                S.add(RVA, "EntryPoint", null);

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64EC_METADATA_REDIRECTION": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_ARM64EC_METADATA_REDIRECTION", 0);

                S.add(RVA, "From", null);
                S.add(RVA, "To", null);

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_ARM64EC_METADATA_REDIRECTION", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY": {
                StructureDataType S =
                    new StructureDataType("_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", 0);

                S.add(RVA, "BeginAddress", null);

                StructureDataType T =
                    new StructureDataType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_PACKED", 0);
                {
                    T.setPackingEnabled(true);
                    addBitField(T, ULONG, 2, "Flag", null);
                    addBitField(T, ULONG, 11, "FunctionLength", null);
                    addBitField(T, ULONG, 3, "RegF", null);
                    addBitField(T, ULONG, 4, "RegI", null);
                    addBitField(T, ULONG, 1, "H", null);
                    addBitField(T, ULONG, 2, "CR", null);
                    addBitField(T, ULONG, 9, "FrameSize", null);
                    typeManager.addDataType(T, DEFAULT_TYPE_CONFLICT_HANDLER);
                }

                S.add(T, "packed", null);

                TypedefDataType typedef =
                    new TypedefDataType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", S);
                return Optional.of(
                    typeManager.addDataType(typedef, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64_RUNTIME_FUNCTION_UNPACKED_ENTRY": {
                StructureDataType S =
                    new StructureDataType("IMAGE_ARM64_RUNTIME_FUNCTION_UNPACKED_ENTRY", 0);

                S.add(RVA, "BeginAddress", null);
                S.add(RVA, "ExceptionInfoRVA", null);

                return Optional.of(
                    typeManager.addDataType(S, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }


            case "IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA": {
                StructureDataType S =
                    new StructureDataType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA", 0);

                S.setPackingEnabled(true);
                addBitField(S, ULONG, 18, "FunctionLength", null);
                addBitField(S, ULONG, 2, "Version", null);
                addBitField(S, ULONG, 1, "ExceptionDataPresent", null);
                addBitField(S, ULONG, 1, "EpilogInHeader", null);
                addBitField(S, ULONG, 5, "EpilogCount", null);
                addBitField(S, ULONG, 5, "CodeWords", null);

                return Optional.of(
                    typeManager.addDataType(S, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED": {
                StructureDataType S =
                    new StructureDataType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED", 0);

                S.setPackingEnabled(true);
                addBitField(S, ULONG, 16, "ExtendedEpilogCount", null);
                addBitField(S, ULONG, 8, "ExtendedCodeWords", null);

                return Optional.of(
                    typeManager.addDataType(S, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "IMAGE_ARM64_RUNTIME_FUNCTION_EXTENDED_ENTRY": {
                StructureDataType S =
                    new StructureDataType("IMAGE_ARM64_RUNTIME_FUNCTION_EXTENDED_ENTRY", 0);
                S.add(getType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA").get(), "base", null);
                S.add(getType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED").get(), "extension", null);

                return Optional.of(
                    typeManager.addDataType(S, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }

            case "EpilogScope": {
                StructureDataType S =
                    new StructureDataType("EpilogScope", 0);

                S.setPackingEnabled(true);
                addBitField(S, ULONG, 18, "StartOffset", null);
                addBitField(S, ULONG, 4, "Res", null);
                addBitField(S, ULONG, 10, "ExceptionDataPresent", null);

                return Optional.of(
                    typeManager.addDataType(S, DEFAULT_TYPE_CONFLICT_HANDLER)
                );
            }
        }
        return super.getType(name);
    }

    @Override
    public CategoryPath getCategoryPath() {
        return super.getCategoryPath().extend("PE");
    }
}
