package lief.ghidra.plugins.analyzers.pe;

import java.util.OptionalLong;

import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import lief.pe.ExceptionInfo;
import lief.pe.RuntimeFunctionAArch64;
import lief.pe.RuntimeFunctionX64;
import lief.pe.aarch64.PackedFunction;
import lief.pe.aarch64.UnpackedFunction;
import lief.pe.Binary;

import lief.ghidra.plugins.analyzers.Context;
import lief.ghidra.plugins.analyzers.LIEFAbstractAnalyzer;
import lief.ghidra.plugins.analyzers.TypeBuilder;

public class ExceptionsAnalyzer extends LIEFAbstractAnalyzer {
    private final static String NAME = "LIEF - PE Exceptions";
    private final static String DESCRIPTION =
        """
        Recognize x86-64/ARM64 exceptions info and define the associated
        structures
        """;

    public ExceptionsAnalyzer() {
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
        for (ExceptionInfo exception : ctx.getBin().getExceptions()) {
            process(ctx, exception);
        }
        return true;
    }

    private void process(Context<Binary> ctx, ExceptionInfo e) {
        if (e instanceof RuntimeFunctionX64) {
            process(ctx, (RuntimeFunctionX64)e);
            return;
        }

        if (e instanceof RuntimeFunctionAArch64) {
            process(ctx, (RuntimeFunctionAArch64)e);
            return;
        }
    }

    private void process(Context<Binary> ctx, RuntimeFunctionAArch64 e) {
        // Note(romain): Current version of Ghidra (11.4) does not support
        // multiple architectures at the same time. Therefore, we just create a
        // symbol for the (ARM64) function
        Address addr = ctx.translateAddress(e.getRVA());
        ctx.createSymbolIfNeeded("__aarch64_function", addr);

        if (e instanceof PackedFunction) {
            process(ctx, (PackedFunction)e);
            return;
        }

        if (e instanceof UnpackedFunction) {
            process(ctx, (UnpackedFunction)e);
            return;
        }
    }

    private void process(Context<Binary> ctx, RuntimeFunctionX64 e) {
        // Ghidra already supports x86-64 exceptions info so we can skip it
    }

    private void process(Context<Binary> ctx, PackedFunction e) {
        OptionalLong optAddr = ctx.getBin().offsetToVirtualAddress(e.getOffset());
        if (!optAddr.isPresent()) {
            ctx.getLog().appendMsg(String.format(
                    "Can't convert offset %#x into an address", e.getOffset()));
            return;
        }
        TypeBuilder<Binary> typeBuilder = ctx.getTypeBuilder();
        Address addr = ctx.translateAddress(optAddr.getAsLong());
        ctx.defineData(addr,
                typeBuilder.getType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY").get()
        );
    }

    private void process(Context<Binary> ctx, UnpackedFunction e) {
        DataType RVA = TypeBuilder.RVA;

        OptionalLong optAddr = ctx.getBin().offsetToVirtualAddress(e.getOffset());
        if (!optAddr.isPresent()) {
            ctx.getLog().appendMsg(String.format(
                    "Can't convert offset %#x into an address", e.getOffset()));
            return;
        }

        TypeBuilder<Binary> typeBuilder = ctx.getTypeBuilder();
        Address addr = ctx.translateAddress(optAddr.getAsLong());

        ctx.defineData(addr,
                typeBuilder.getType("IMAGE_ARM64_RUNTIME_FUNCTION_UNPACKED_ENTRY").get()
        );

        Address xdataAddr = ctx.translateAddress(e.getXdataRVA());

        if (e.isExtended()) {
            ctx.defineData(xdataAddr,
                    typeBuilder.getType("IMAGE_ARM64_RUNTIME_FUNCTION_EXTENDED_ENTRY").get()
            );
        } else {
            ctx.defineData(xdataAddr,
                    typeBuilder.getType("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA").get()
            );
        }

        byte[] unwindCode = e.getUnwindCode();
        if (e.getUnwindCodeOffset() > 0 && unwindCode.length > 0) {
            Address target = xdataAddr.add(e.getUnwindCodeOffset());
            ctx.defineBlob(target, unwindCode.length);
            ctx.createSymbolIfNeeded("__arm64_unwind_code", target);
        }

        if (e.getExceptionHandlerOffset() > 0) {
            Address target = xdataAddr.add(e.getExceptionHandlerOffset());
            ctx.defineData(target, RVA);
            ctx.createSymbolIfNeeded("__arm64_runtime_function_exception_handler", target);
        }

        if (e.getEpilogScopesOffset() > 0 && e.getNbEpilogScopes() > 0) {
            Address target = xdataAddr.add(e.getEpilogScopesOffset());
            ctx.defineData(target,
                new ArrayDataType(
                    typeBuilder.getType("EpilogScope").get(),
                    (int)e.getNbEpilogScopes())
            );
            ctx.createSymbolIfNeeded("__arm64_epilog_scopes", target);
        }
    }
}
