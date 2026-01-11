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
package lief.ghidra.plugins.analyzers;

import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import lief.generic.Binary;
import lief.ghidra.core.FSRLHelper;

public class Context<T> {
    private Program program;
    private T binary;
    TaskMonitor monitor;
    MessageLog log;

    protected Context(Program program, T binary, TaskMonitor monitor,
                      MessageLog log)
    {
        this.program = program;
        this.binary = binary;
        this.monitor = monitor;
        this.log = log;
    }

    public boolean is64bits() {
        return getProgram().getDefaultPointerSize() == 8;
    }

    public boolean is32bits() {
        return getProgram().getDefaultPointerSize() == 4;
    }

    public TypeBuilder<T> getTypeBuilder() {
        if (this.binary instanceof lief.pe.Binary) {
            return new lief.ghidra.plugins.analyzers.pe.TypeBuilder<T>(this);
        }
        return new TypeBuilder<T>(this);
    }

    public static <T> Context<T>
        create(Program program, TaskMonitor monitor, MessageLog log)
    {
        FSRL fsrl = FSRL.fromProgram(program);
        T bin = null;
        try {
            bin = (T)FSRLHelper.load(fsrl);
        } catch (Exception e) {
            log.appendException(e);
            return null;
        }

        if (bin == null || !(bin instanceof T)) {
            log.appendMsg("Can't load binary");
            return null;
        }
        return new Context<T>(program, bin, monitor, log);
    }

    public T getBin() {
        return binary;
    }

    public Binary getGeneric() {
        return (Binary)binary;
    }

    public Program getProgram() {
        return program;
    }

    public TaskMonitor getMonitor() {
        return monitor;
    }

    public MessageLog getLog() {
        return log;
    }

    public Address translateAddress(long address) {
        long imageBase = getGeneric().getImageBase();
        if (address >= imageBase) {
            return program.getImageBase().add(address - getGeneric().getImageBase());
        }
        return program.getImageBase().add(address);
    }

    public boolean defineBlob(Address addr, int length) {
        try {
            DataUtilities.createData(program, addr,
                new ArrayDataType(ByteDataType.dataType, length, 1), /*length*/-1,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
            return true;
        } catch (CodeUnitInsertionException e) {
            getLog().appendException(e);
            return false;
        }
    }

    public boolean defineData(Address addr, DataType ty) {
        try {
            DataUtilities.createData(program, addr, ty, /*length*/-1,
                    ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            return true;
        } catch (CodeUnitInsertionException e) {
            getLog().appendException(e);
            return false;
        }
    }

    public Symbol createSymbolIfNeeded(String symbolPrefix, Address symbolAddress) {
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol primarySymbol = symbolTable.getPrimarySymbol(symbolAddress);
        if (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT) {
          return null;
        }
        String addressAppendedName =
          SymbolUtilities.getAddressAppendedName(symbolPrefix, symbolAddress);
        try {
            return symbolTable.createLabel(symbolAddress, addressAppendedName, SourceType.ANALYSIS);
        } catch (InvalidInputException e) {
            getLog().appendException(e);
            return null;
        }
    }
}
