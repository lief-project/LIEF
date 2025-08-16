package lief.ghidra.plugins.analyzers.pe;

import java.util.Optional;

import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import lief.pe.CHPEMetadata;
import lief.pe.CHPEMetadataARM64;
import lief.pe.CHPEMetadataX86;
import lief.pe.DataDirectory;
import lief.pe.LoadConfiguration;
import lief.pe.Binary;

import lief.ghidra.plugins.analyzers.Context;
import lief.ghidra.plugins.analyzers.LIEFAbstractAnalyzer;
import lief.ghidra.plugins.analyzers.TypeBuilder;

public class LoadConfigurationAnalyzer extends LIEFAbstractAnalyzer {

    private final static String NAME = "LIEF - PE LoadConfiguration";
    private final static String DESCRIPTION =
        """
        Enhance type definitions for PE LoadConfiguration and its related structures
        like `IMAGE_ARM64EC_METADATA`
        """;

    public LoadConfigurationAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return PEUtil.canAnalyze(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        Context<Binary> ctx = Context.create(program, monitor, log);
        if (ctx == null) {
            return false;
        }

        Optional<LoadConfiguration> optLoadConfig = ctx.getBin().getLoadConfiguration();
        if (optLoadConfig.isEmpty()) {
            return true;
        }

        LoadConfiguration loadConfig = optLoadConfig.get();

        TypeBuilder<Binary> typeBuilder = ctx.getTypeBuilder();

        DataType U32 = TypeBuilder.U32;
        DataType U16 = TypeBuilder.U16;
        DataType RVA = TypeBuilder.RVA;
        DataType UPTR = typeBuilder.getUnsignedPointer();
        DataType ADDR = typeBuilder.getAddrType();

        String suffix = ctx.is32bits() ? "32" : "64";
        String baseName = String.format("IMAGE_LOAD_CONFIG_DIRECTORY%s", suffix);

        StructureDataType struct = new StructureDataType("_" + baseName, 0);
        struct.add(U32, "Size", null);
        struct.add(U32, "TimeDateStamp", null);
        struct.add(U16, "MajorVersion", null);
        struct.add(U16, "MinorVersion", null);
        struct.add(U32, "GlobalFlagsClear", null);
        struct.add(U32, "GlobalFlagsSet", null);
        struct.add(U32, "CriticalSectionDefaultTimeout", null);
        struct.add(UPTR, "DeCommitFreeBlockThreshold", null);
        struct.add(UPTR, "DeCommitTotalFreeThreshold", null);
        struct.add(ADDR, "LockPrefixTable", null);
        struct.add(UPTR, "MaximumAllocationSize", null);
        struct.add(UPTR, "VirtualMemoryThreshold", null);
        struct.add(UPTR, "ProcessAffinityMask", null);
        struct.add(U32, "ProcessHeapFlags", null);
        struct.add(U16, "CSDVersion", null);
        struct.add(U16, "DependentLoadFlags", null);
        struct.add(ADDR, "EditList", null);
        struct.add(ADDR, "SecurityCookie", null);

        if (loadConfig.getSEHandlerTable().isPresent()) {
            struct.add(typeBuilder.getPointer(UPTR), "SEHandlerTable", null);
        }

        if (loadConfig.getSEHandlerCount().isPresent()) {
            struct.add(UPTR, "SEHandlerCount", null);
        }

        if (loadConfig.getGuardCfcCheckFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardCFCheckFunctionPointer", null);
        }

        if (loadConfig.getGuardCfDispatchFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardCFDispatchFunctionPointer", null);
        }

        if (loadConfig.getGuardCfFunctionTable().isPresent()) {
            struct.add(typeBuilder.getPointer(U32), "GuardCFFunctionTable", null);
        }

        if (loadConfig.getGuardCfFunctionCount().isPresent()) {
            struct.add(UPTR, "GuardCFFunctionCount", null);
        }

        if (loadConfig.getGuardFlags().isPresent()) {
            struct.add(typeBuilder.getType("IMAGE_GUARD_FLAGS").get(),
                       "GuardFlags", null);
        }

        if (loadConfig.getCodeIntegrity().isPresent()) {
            struct.add(
                typeBuilder.getType("IMAGE_LOAD_CONFIG_CODE_INTEGRITY").get(),
                "CodeIntegrity", null);
        }

        if (loadConfig.getGuardAddressTakenIatEntryTable().isPresent()) {
            struct.add(ADDR, "GuardAddressTakenIatEntryTable", null);
        }

        if (loadConfig.getGuardAddressTakenIatEntryCount().isPresent()) {
            struct.add(UPTR, "GuardAddressTakenIatEntryCount", null);
        }

        if (loadConfig.getGuardLongJumpTargetTable().isPresent()) {
            struct.add(ADDR, "GuardLongJumpTargetTable", null);
        }

        if (loadConfig.getGuardLongJumpTargetCount().isPresent()) {
            struct.add(UPTR, "GuardLongJumpTargetCount", null);
        }

        if (loadConfig.getDynamicValueRelocTable().isPresent()) {
            struct.add(ADDR, "DynamicValueRelocTable", null);
        }

        if (loadConfig.getCHPEMetadataPointer().isPresent()) {
            long targetAddr = loadConfig.getCHPEMetadataPointer().getAsLong();
            Address address = ctx.translateAddress(targetAddr);
            Optional<CHPEMetadata> metadata = loadConfig.getCHPEMetadata();
            if (metadata.isPresent() && (metadata.get() instanceof CHPEMetadataARM64)) {
                CHPEMetadataARM64 arm64 = (CHPEMetadataARM64)metadata.get();
                DataType Ty = null;
                switch (arm64.getVersion()) {
                    case 2: {
                        Ty = typeBuilder.getType("IMAGE_ARM64EC_METADATA_V2").get();
                        break;
                    }
                    default: {
                        Ty = typeBuilder.getType("IMAGE_ARM64EC_METADATA").get();
                        break;
                    }
                }
                ctx.defineData(address, Ty);
                struct.add(typeBuilder.getPointer(Ty), "CHPEMetadataPointer", null);
                process(ctx, loadConfig, arm64);
            } else if (metadata.isPresent() && (metadata.get() instanceof CHPEMetadataX86)) {
                CHPEMetadataX86 x86 = (CHPEMetadataX86)metadata.get();
                DataType Ty = null;
                switch (x86.getVersion()) {
                    case 2: {
                        Ty = typeBuilder.getType("IMAGE_CHPE_METADATA_X86_V2").get();
                        break;
                    }
                    case 3: {
                        Ty = typeBuilder.getType("IMAGE_CHPE_METADATA_X86_V3").get();
                        break;
                    }
                    default: {
                        Ty = typeBuilder.getType("IMAGE_CHPE_METADATA_X86").get();
                        break;
                    }
                }
                ctx.defineData(address, Ty);
                struct.add(typeBuilder.getPointer(Ty), "CHPEMetadataPointer", null);
            } else {
                struct.add(ADDR, "CHPEMetadataPointer", null);
            }
        }

        if (loadConfig.getGuardRfFailureRoutine().isPresent()) {
            struct.add(ADDR, "GuardRFFailureRoutine", null);
        }

        if (loadConfig.getGuardRfFailureRoutineFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardRFFailureRoutineFunctionPointer", null);
        }

        if (loadConfig.getDynamicValueRelocTableOffset().isPresent()) {
            struct.add(RVA, "DynamicValueRelocTableOffset", null);
        }

        if (loadConfig.getDynamicValueRelocTableSection().isPresent()) {
            struct.add(U16, "DynamicValueRelocTableSection", null);
        }

        if (loadConfig.getReserved2().isPresent()) {
            struct.add(U16, "Reserved2", null);
        }

        if (loadConfig.getGuardRfVerifyStackPointerFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardRFVerifyStackPointerFunctionPointer", null);
        }

        if (loadConfig.getHotPatchTableOffset().isPresent()) {
            struct.add(RVA, "HotPatchTableOffset", null);
        }

        if (loadConfig.getReserved3().isPresent()) {
            struct.add(U32, "Reserved3", null);
        }

        if (loadConfig.getEnclaveConfigurationPointer().isPresent()) {
            struct.add(ADDR, "EnclaveConfigurationPointer", null);
        }

        if (loadConfig.getVolatileMetadataPointer().isPresent()) {
            struct.add(ADDR, "VolatileMetadataPointer", null);
        }

        if (loadConfig.getGuardEHContinuationTable().isPresent()) {
            struct.add(ADDR, "GuardEHContinuationTable", null);
        }

        if (loadConfig.getGuardEHContinuationCount().isPresent()) {
            struct.add(UPTR, "GuardEHContinuationCount", null);
        }

        if (loadConfig.getGuardXfgCheckFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardXFGCheckFunctionPointer", null);
        }

        if (loadConfig.getGuardXfgDispatchFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardXFGDispatchFunctionPointer", null);
        }

        if (loadConfig.getGuardXfgTableDispatchFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardXFGTableDispatchFunctionPointer", null);
        }

        if (loadConfig.getCastGuardOsDeterminedFailureMode().isPresent()) {
            struct.add(ADDR, "CastGuardOsDeterminedFailureMode", null);
        }

        if (loadConfig.getGuardMemcpyFunctionPointer().isPresent()) {
            struct.add(ADDR, "GuardMemcpyFunctionPointer", null);
        }

        if (loadConfig.getUmaFunctionPointers().isPresent()) {
            struct.add(ADDR, "UmaFunctionPointers", null);
        }

        struct.setCategoryPath(typeBuilder.getCategoryPath());

        TypedefDataType loadConfigTy = new TypedefDataType(baseName, struct);
        DataDirectory loadConfigDir = ctx.getBin().getLoadConfigurationDir().get();
        Address address = ctx.translateAddress(loadConfigDir.getRVA());

        ctx.defineData(address, loadConfigTy);
        return true;
    }

    private void process(Context<Binary> ctx, LoadConfiguration loadconfig,
                         CHPEMetadataARM64 arm64)
    {
        TypeBuilder<Binary> typeBuilder = ctx.getTypeBuilder();
        if (arm64.getCodeMap() > 0 && arm64.getCodeMapCount() > 0) {
            Address address = ctx.translateAddress(arm64.getCodeMap());
            ctx.defineData(address,
                new ArrayDataType(
                    typeBuilder.getType("IMAGE_ARM64EC_METADATA_CODE_RANGE").get(),
                    arm64.getCodeMapCount())
            );
        }
        if (arm64.getCodeRangesToEntrypoints() > 0 && arm64.getCodeRangesToEntryPointsCount() > 0) {
            Address address = ctx.translateAddress(arm64.getCodeRangesToEntrypoints());
            ctx.defineData(address,
                new ArrayDataType(
                    typeBuilder.getType("IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT").get(),
                    arm64.getCodeRangesToEntryPointsCount())
            );
        }

        if (arm64.getRedirectionMetadata() > 0 && arm64.getRedirectionMetadataCount() > 0) {
            Address address = ctx.translateAddress(arm64.getRedirectionMetadata());
            ctx.defineData(address,
                new ArrayDataType(
                    typeBuilder.getType("IMAGE_ARM64EC_METADATA_REDIRECTION").get(),
                    arm64.getRedirectionMetadataCount())
            );
        }
    }
}
