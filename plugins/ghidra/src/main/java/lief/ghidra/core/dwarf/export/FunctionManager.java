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

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;

import ghidra.util.Msg;

import java.util.ArrayList;

public class FunctionManager {
    private CompilationUnit owner;
    private TypeManager typeManager;
    private Program currentProgram;
    private long imagebase;

    public FunctionManager(
        Program program, CompilationUnit unit, TypeManager typeManager,
        long imagebase)
    {
        owner = unit;
        this.typeManager = typeManager;
        this.currentProgram = program;
        this.imagebase = imagebase;
    }

    public long getDeltaImageBase() {
        return currentProgram.getImageBase().getOffset() - imagebase;
    }

    public void add(Function func) {
        Msg.debug(null, String.format("Function: %#x: %s %s %s",
            func.getEntryPoint().getOffset(), func.getName(),
            func.getSymbol().getName(),
            func.getParentNamespace().getName()));

        lief.dwarf.editor.Function dwFunc = owner.createFunction(computeName(func));
        computeRange(func, dwFunc);

        if (func.isExternal()) {
            dwFunc.setExternal();
        }

        for (Parameter p : func.getParameters()) {
            Msg.debug(FunctionManager.class, String.format("  %s -> %s (%s)", p.getName(),
                p.getDataType().toString(), p.getDataType().getClass().getName()
            ));
            computeParameter(func, dwFunc, p);
        }
        dwFunc.setReturnType(typeManager.addType(func.getReturnType()));

        for (ghidra.program.model.listing.Variable local : func.getStackFrame().getLocals()) {
            computeVariable(func, dwFunc, local);
        }
    }

    private lief.dwarf.editor.Function
        computeParameter(Function func, lief.dwarf.editor.Function dwFunc,
                         Parameter param)
    {
        dwFunc.addParameter(
            param.getName(),
            typeManager.addType(param.getDataType())
        );
        return dwFunc;
    }

    private String computeName(Function func) {
        return func.getName(/*includeNamespacePath=*/true);
    }

    private lief.dwarf.editor.Function
        computeVariable(Function func, lief.dwarf.editor.Function dwFunc,
                        ghidra.program.model.listing.Variable local)
    {
        Variable stackvar = dwFunc.createStackVariable(local.getName());
        stackvar.setType(typeManager.addType(local.getDataType()));
        stackvar.setStackOffset(-local.getStackOffset());
        return dwFunc;
    }


    private lief.dwarf.editor.Function computeRange(
        Function func, lief.dwarf.editor.Function dwFunc)
    {
        AddressSetView body = func.getBody();

        if (body.isEmpty()) {
            dwFunc.setAddress(
                func.getEntryPoint().getOffset() - getDeltaImageBase()
            );
            return dwFunc;
        }

        if (body.getNumAddressRanges() == 1) {
            AddressRange range = body.getFirstRange();
            dwFunc.setLowHigh(
                range.getMinAddress().getOffset() - getDeltaImageBase(),
                range.getMaxAddress().getOffset() - getDeltaImageBase()
            );
            return dwFunc;
        }

        ArrayList<lief.dwarf.editor.Function.Range> ranges
            = new ArrayList<>(body.getNumAddressRanges());

        for (AddressRange range : body) {
            ranges.add(new lief.dwarf.editor.Function.Range(
                range.getMinAddress().getOffset() - getDeltaImageBase(),
                range.getMaxAddress().getOffset() - getDeltaImageBase()
            ));
        }
        dwFunc.setRanges(ranges);
        return dwFunc;
    }
}
