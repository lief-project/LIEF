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

import lief.dwarf.editor.CompilationUnit;

import lief.dwarf.editor.Variable;

import ghidra.program.model.listing.Data;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class DataManager {
    private CompilationUnit owner;
    private TypeManager typeManager;
    private Program currentProgram;
    private long imagebase;

    public DataManager(
        Program program, CompilationUnit unit, TypeManager typeManager, long imagebase)
    {
        owner = unit;
        this.typeManager = typeManager;
        this.currentProgram = program;
        this.imagebase = imagebase;
    }

    public long getDeltaImageBase() {
        return currentProgram.getImageBase().getOffset() - imagebase;
    }

    public Variable add(Data data) {
        Msg.debug(DataManager.class, String.format(
            "Adding data: %s (%s)",
            data.toString(), data.getClass().getName()
        ));
        if (!data.getAddress().hasSameAddressSpace(currentProgram.getImageBase())) {
            return null;
        }
        long address = data.getAddress().getOffset() - getDeltaImageBase();
        String name = computeName(data);

        Msg.debug(DataManager.class, String.format("%s: %#x", name, address));

        Variable dwVar = owner.createVariable(
            name
        );
        dwVar.setAddr(address);
        dwVar.setType(this.typeManager.addType(data.getDataType()));
        return dwVar;
    }

    public String computeName(Data data) {
        String pathName = data.getPathName();
        if (pathName != null) {
            return pathName;
        }
        return String.format("var_%#x",
            data.getAddress().getOffset() - getDeltaImageBase()
        );
    }
}
