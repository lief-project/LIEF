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

import java.util.Optional;

import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IBO32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.SignedQWordDataType;
import ghidra.program.model.data.SignedWordDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;

public class TypeBuilder<T> {
    protected static final DataTypeConflictHandler DEFAULT_TYPE_CONFLICT_HANDLER = DataTypeConflictHandler.REPLACE_HANDLER;
    public static final CategoryPath ROOT = new CategoryPath("/LIEF");

    public final static DataType U8 = ByteDataType.dataType;
    public final static DataType I8 = SignedByteDataType.dataType;

    public final static DataType U16 = WordDataType.dataType;
    public final static DataType I16 = SignedWordDataType.dataType;

    public final static DataType U32 = DWordDataType.dataType;
    public final static DataType I32 = SignedDWordDataType.dataType;

    public final static DataType U64 = QWordDataType.dataType;
    public final static DataType I64 = SignedQWordDataType.dataType;

    public final static DataType RVA = IBO32DataType.dataType;

    protected Context<T> context;

    public TypeBuilder(Context<T> context) {
        this.context = context;
    }

    public DataType getPointer(DataType target) {
        DataTypeManager dataTypeManager = context.getProgram().getDataTypeManager();
        return new PointerDataType(target,
                context.getProgram().getDefaultPointerSize(), dataTypeManager);
    }

    public DataType getVoidPointer() {
        DataTypeManager dataTypeManager = context.getProgram().getDataTypeManager();
        return getPointer(new VoidDataType(dataTypeManager));
    }

    public DataType getFunctionPointer(String name) {
        DataTypeManager dataTypeManager = context.getProgram().getDataTypeManager();
        return getPointer(new FunctionDefinitionDataType(
            name, dataTypeManager
        ));
    }

    public DataType getUnsignedPointer() {
        if (context.getProgram().getDefaultPointerSize() == U32.getLength()) {
            return U32;
        }

        if (context.getProgram().getDefaultPointerSize() == U64.getLength()) {
            return U64;
        }
        return null;
    }

    public Optional<DataType> tryGetType(String name) {
        DataType ty = context
            .getProgram()
            .getDataTypeManager()
            .getDataType(getCategoryPath(), name);

        if (ty == null) {
            return Optional.empty();
        }
        return Optional.of(ty);
    }

    public Optional<DataType> getType(String name) {
        Optional<DataType> ty = tryGetType(name);
        if (ty.isPresent()) {
            return ty;
        }
        try {
            return Optional.of(createType(name));
        } catch (Exception e) {
            Msg.error(TypeBuilder.class,
                    String.format("Unknown type '%s'", name));
            return Optional.empty();
        }
    }

    protected DataType createType(String name) throws NotYetImplementedException {
        throw new NotYetImplementedException("Type: '" + name + "' not implemented");
    }

    public CategoryPath getCategoryPath() {
        return TypeBuilder.ROOT;
    }

    public DataType getAddrType() {
        return new PointerDataType(
            null, context.getProgram().getDefaultPointerSize(),
            context.getProgram().getDataTypeManager()
        );
    }
}
