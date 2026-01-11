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
package lief.ghidra.core.dwarf.export;

import java.io.File;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.Application;
import ghidra.framework.ApplicationProperties;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import lief.Utils;
import lief.dwarf.Editor;
import lief.dwarf.editor.CompilationUnit;
import lief.ghidra.core.FSRLHelper;
import lief.ghidra.util.exception.Exception;

public class Manager {
    private Program currentProgram;

    public Manager(Program currentProgram) {
        this.currentProgram = currentProgram;
    }

    public void export(File output) throws Exception {
        FSRL fsrl = FSRL.fromProgram(currentProgram);
        Object bin = FSRLHelper.load(fsrl);
        if (bin == null || !(bin instanceof lief.generic.Binary)) {
            throw new Exception("Can't load: " + fsrl.toString());
        }
        lief.generic.Binary genericBinary = (lief.generic.Binary)bin;
        Editor editor = Editor.forBinary(genericBinary);
        if (editor == null) {
            throw new Exception("Can't instantiate the DWARF editor for " + fsrl.toString());
        }

        long imagebase = genericBinary.getImageBase();
        Msg.info(Manager.class, String.format(
            "Imagebase: %#x (Ghidra: %#x)", imagebase, currentProgram.getImageBase().getOffset()
        ));

        CompilationUnit unit = editor.createCompilationUnit();
        initMetadata(unit);

        TypeManager typeManager = new TypeManager(unit);
        FunctionManager funcManager =
            new FunctionManager(this.currentProgram, unit, typeManager, imagebase);

        DataManager dataManager =
            new DataManager(this.currentProgram, unit, typeManager, imagebase);

        Listing listing = currentProgram.getListing();

        for (Data data : listing.getDefinedData(/*forward*/true)) {
            dataManager.add(data);
        }

        for (Function func : currentProgram.getFunctionManager().getFunctionsNoStubs(/*forward*/true)) {
            funcManager.add(func);
        }

        editor.write(output.getAbsolutePath());
    }

    private void initMetadata(CompilationUnit unit) {
        ApplicationProperties props = Application.getApplicationLayout().getApplicationProperties();
        Utils.Version version = Utils.getExtendedVersion();

        unit.setProducer(String.format("Ghidra %s with LIEF %d.%d.%d.%d",
            props.getApplicationVersion(),
            version.major(), version.minor(), version.patch(), version.id()
        ));
    }

}
