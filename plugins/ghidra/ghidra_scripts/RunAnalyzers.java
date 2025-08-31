import lief.ghidra.plugins.analyzers.pe.LoadConfigurationAnalyzer;
import lief.ghidra.plugins.analyzers.pe.ExceptionsAnalyzer;
import lief.ghidra.plugins.analyzers.elf.RelocationsAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.exporter.AsciiExporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.Option;
import ghidra.program.model.listing.CodeUnit;

import java.io.File;
import java.util.List;

public class RunAnalyzers extends GhidraScript {
    @Override
    public void run() throws Exception {
        MessageLog log = new MessageLog();
        String prefix = System.getProperty("lief.test.prefix");
        File testDir = new File(System.getProperty("lief.test.dir"));
        if (!testDir.isDirectory()) {
            throw new RuntimeException(String.format("%s does not exist", testDir.getAbsolutePath()));
        }
        AsciiExporter exporter = new AsciiExporter();
        List<Option> options = exporter.getOptions(null);
        for (Option opt : options) {
            if (opt.getGroup().trim() == "Field Widths") {
                opt.setValue((int)opt.getValue() * 2 + 4);
            }
        }
        exporter.setOptions(options);

        File original = new File(testDir.getAbsolutePath() + "/" + prefix + "original.txt");
        exporter.export(original, currentProgram, null, monitor);
        {
            Analyzer analyzer = new LoadConfigurationAnalyzer();
            if (analyzer.canAnalyze(currentProgram)) {
                analyzer.added(currentProgram, currentProgram.getAddressFactory().getAddressSet(),
                               monitor, log);
            }
        }
        {
            Analyzer analyzer = new ExceptionsAnalyzer();
            if (analyzer.canAnalyze(currentProgram)) {
                analyzer.added(currentProgram, currentProgram.getAddressFactory().getAddressSet(),
                               monitor, log);
            }
        }

        {
            Analyzer analyzer = new RelocationsAnalyzer();
            if (analyzer.canAnalyze(currentProgram)) {
                analyzer.added(currentProgram, currentProgram.getAddressFactory().getAddressSet(),
                               monitor, log);
            }
        }
        log.write(RunAnalyzers.class, "RunAnalyzers");

        File updated = new File(testDir.getAbsolutePath() + "/" + prefix + "updated.txt");
        exporter.export(updated, currentProgram, null, monitor);
    }
}
