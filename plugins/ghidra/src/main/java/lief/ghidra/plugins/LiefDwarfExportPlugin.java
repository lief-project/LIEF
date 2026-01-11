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
package lief.ghidra.plugins;

import lief.ghidra.LiefPluginPackage;
import lief.ghidra.core.NativeBridge;
import lief.ghidra.core.dwarf.export.Manager;
import lief.Constants;
import lief.Utils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OkDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.swing.JOptionPane;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = LiefPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Export as DWARF",
    description = "Export Ghidra information as an external DWARF file"
)
//@formatter:on
public class LiefDwarfExportPlugin extends ProgramPlugin {
    private DockingAction actionExportAsDwarf;
    private File lastSelectedDir = null;

    public LiefDwarfExportPlugin(PluginTool tool) {
        super(tool);
        setupActions();
    }

    private void setupActions() {
        actionExportAsDwarf = new DockingAction("Export as DWARF", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                exportAsDWARF();
            }
        };

        actionExportAsDwarf.setMenuBarData(new MenuData(new String[] {
          "LIEF", "Export as DWARF"
        }, /*group=*/"Debug Info"));

        tool.addAction(actionExportAsDwarf);
    }

    protected void exportAsDWARF() {
        NativeBridge.init();
        if (!NativeBridge.isLoaded()) {
            return;
        }

        if (!Utils.isExtended()) {
            JOptionPane.showMessageDialog(null,
                "This feature requires LIEF extended.\n" +
                "Please visit: " + Constants.WEBSITE,
                "LIEF", JOptionPane.WARNING_MESSAGE);
            return;
        }

        GhidraFileChooser chooser = new GhidraFileChooser(null);
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setTitle("LIEF DWARF Export");
        chooser.setApproveButtonText("Select");

        if (lastSelectedDir != null) {
            chooser.setCurrentDirectory(lastSelectedDir);
        }

        File selectedFile = chooser.getSelectedFile();

        if (selectedFile == null) {
            return;
        }

        lastSelectedDir = selectedFile.getParentFile();

        if (selectedFile.exists()) {
            try {
                Files.deleteIfExists(Path.of(selectedFile.toURI()));
                if (!selectedFile.createNewFile()) {
                    OkDialog.showError("LIEF DWARF Export",
                        String.format("Can't create file: '%s'",
                            selectedFile.getPath()
                        )
                    );
                }
            } catch (Exception e) {
                Msg.showError(LiefDwarfExportPlugin.class, null,
                    "Exception", "Exception", e
                );
            }
        }

        Manager manager = new Manager(currentProgram);
        try {
            manager.export(selectedFile);
        } catch (Exception e) {
            Msg.showError(LiefDwarfExportPlugin.class, null,
                "Exception", "Exception", e
            );
            return;
        }
        OkDialog.showInfo("LIEF DWARF Export",
            String.format("DWARF exported here: '%s'",
                selectedFile.getPath()
            )
        );
    }

    @Override
    protected void init() {
        Msg.info(LiefDwarfExportPlugin.class, String.format(
            "%s initialized", LiefDwarfExportPlugin.class.getName()
        ));
    }
}
