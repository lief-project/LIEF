import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JOptionPane;

import docking.widgets.OkDialog;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.file.formats.dump.mdmp.Minidump;
import ghidra.framework.data.GhidraFile;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import lief.Constants;
import lief.Utils;
import lief.ghidra.core.NativeBridge;
import lief.ghidra.core.dwarf.export.Manager;

public class DwarfExporter extends Exporter {
    public DwarfExporter() {
        super("DWARF", "dwarf", new HelpLocation("ExporterPlugin", "dwarf"));
    }

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        return EMPTY_OPTIONS;
    }

    @Override
    public void setOptions(List<Option> options) throws OptionException {
    }

    @Override
    public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
                          TaskMonitor monitor) throws IOException, ExporterException
    {
        Msg.debug(DwarfExporter.class, String.format(
            "Exporting '%s' (%s) into %s",
            domainObj.toString(), domainObj.getClass().getName(),
            file.getAbsolutePath()
        ));

        Program currentProgram = (Program)domainObj;

        NativeBridge.init();

        if (!NativeBridge.isLoaded()) {
            return false;
        }

        if (!Utils.isExtended()) {
            JOptionPane.showMessageDialog(null,
                "This feature requires LIEF extended.\n" +
                "Please visit: " + Constants.WEBSITE,
                "LIEF", JOptionPane.WARNING_MESSAGE);
            return false;
        }

        Manager manager = new Manager(currentProgram);
        try {
            manager.export(file);
        } catch (Exception e) {
            Msg.showError(DwarfExporter.class, null,
                "Exception", "Exception", e
            );
            return false;
        }
        OkDialog.showInfo("LIEF DWARF Export",
            String.format("DWARF exported here: '%s'",
                file.getPath()
            )
        );

        return true;
    }

    @Override
    public boolean export(File file, DomainFile domainFile, TaskMonitor monitor)
    {
        Msg.debug(DwarfExporter.class, String.format(
            "Exporting '%s' (%s) into %s",
            domainFile.toString(), domainFile.getClass().getName(),
            file.getAbsolutePath()
        ));

        try {
            DomainObject domainObj = domainFile.getReadOnlyDomainObject(
                this, DomainFile.DEFAULT_VERSION, monitor
            );
            return export(file, domainObj, null, monitor);
        } catch (CancelledException e) {
            return false;
        } catch (VersionException | IOException | ExporterException e) {
            Msg.showError(DwarfExporter.class, null, "DWARF Exporter",
                "Error while trying to retreive the program", e
            );
            return false;
        }
    }

    @Override
    public boolean supportsAddressRestrictedExport() {
        return false;
    }

    @Override
    public boolean canExportDomainFile(DomainFile domainFile) {
      return canExportDomainObject(domainFile.getDomainObjectClass());
    }

    public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
      return ProgramDB.class.isAssignableFrom(domainObjectClass);
    }

}
