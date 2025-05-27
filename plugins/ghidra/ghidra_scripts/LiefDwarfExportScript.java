import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.Msg;
import lief.Constants;
import lief.Utils;
import lief.ghidra.core.FSRLHelper;
import lief.ghidra.core.NativeBridge;
import lief.ghidra.core.dwarf.export.Manager;
import lief.ghidra.util.exception.Exception;

public class LiefDwarfExportScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        NativeBridge.init();
        if (!NativeBridge.isLoaded()) {
            Msg.error(LiefDwarfExportScript.class, "Can't load native libraries");
            return;
        }
        if (!Utils.isExtended()) {
            Msg.error(LiefDwarfExportScript.class,
                "This feature requires LIEF extended.\n" +
                "Please visit: " + Constants.WEBSITE);
            return;
        }
        FSRL fsrl = FSRL.fromProgram(currentProgram);
        File container = FSRLHelper.getContainerPath(fsrl);
        File output = new File(
            container.getParentFile().getAbsolutePath() + File.separatorChar +
            container.getName() + ".debug"
        );

        Manager manager = new Manager(currentProgram);
        try {
            manager.export(output);
        } catch (Exception e) {
            Msg.showError(LiefDwarfExportScript.class, null,
                "Exception", "Exception", e
            );
            return;
        }

        Msg.info(LiefDwarfExportScript.class, String.format(
            "DWARF file exported to %s", output.toString()
        ));
    }
}
