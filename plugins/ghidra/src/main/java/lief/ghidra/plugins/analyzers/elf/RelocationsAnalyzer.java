package lief.ghidra.plugins.analyzers.elf;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lief.elf.Binary;
import lief.elf.Relocation;
import lief.ghidra.plugins.analyzers.Context;
import lief.ghidra.plugins.analyzers.LIEFAbstractAnalyzer;

public class RelocationsAnalyzer extends LIEFAbstractAnalyzer {

    private final static String NAME = "LIEF - ELF Relocation";
    private final static String DESCRIPTION =
        """
        Add support for relocations not recognized by Ghidra
        """;

    public RelocationsAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
        setDefaultEnablement(false);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return isELF(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        Context<Binary> ctx = Context.create(program, monitor, log);
        if (ctx == null) {
            return false;
        }

        // Not relevant (yet) since Ghidra has a good support for the
        // different ELF relocation formats

        return true;
    }
}
