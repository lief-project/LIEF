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
import lief.dwarf.editor.EnumType;
import lief.dwarf.editor.FunctionType;
import lief.dwarf.editor.StructType;
import lief.dwarf.editor.Type;
import lief.dwarf.editor.BaseType;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.AbstractIntegerDataType;

import ghidra.util.Msg;

import java.util.HashMap;

public class TypeManager {
    private CompilationUnit owner;
    private final HashMap<DataType, Type> cache = new HashMap<DataType, Type>();

    public TypeManager(CompilationUnit unit) {
        owner = unit;
    }

    private Type put(DataType key, Type value) {
        cache.put(key, value);
        return value;
    }

    public Type addType(DataType type) {
        Type ty = cache.get(type);

        if (ty != null) {
            return ty;
        }

        if (type instanceof VoidDataType) {
            return put(type, owner.createVoidType());
        }

        if (type instanceof AbstractIntegerDataType) {
            AbstractIntegerDataType integerType = (AbstractIntegerDataType)type;
            int size = integerType.getLength();
            boolean signed = integerType.isSigned();
            return put(type,
                owner.createBaseType(
                    integerType.getName(), size,
                    signed ? BaseType.Encoding.SIGNED : BaseType.Encoding.UNSIGNED
                )
            );
        }

        if (type instanceof Array) {
            Array arrayType = (Array)type;
            return put(type,
                owner.createArray(
                    arrayType.getName(), addType(arrayType.getDataType()),
                    arrayType.getNumElements()
                )
            );
        }

        if (type instanceof TypeDef) {
            TypeDef typedef = (TypeDef)type;
            return put(type,
                owner.createTypedef(
                    typedef.getName(), addType(typedef.getDataType())
                )
            );
        }

        if (type instanceof Composite) {
            Composite composite = (Composite)type;
            StructType.Type compositeTy =
                (composite instanceof Structure) ? StructType.Type.STRUCT :
                (composite instanceof Union) ? StructType.Type.UNION :
                StructType.Type.STRUCT;

            StructType structTy = (StructType)put(type,
                owner.createStructure(composite.getName(), compositeTy)
            );

            structTy.setSize(composite.getLength());

            for (DataTypeComponent e : composite.getDefinedComponents()) {
                String fieldName = e.getFieldName();
                if (fieldName == null) {
                    fieldName = e.getDefaultFieldName();
                }
                if (fieldName == null) {
                    fieldName = "__unknown__";
                }
                structTy.addMember(fieldName, addType(e.getDataType()),
                                   e.getOffset());
            }
            return structTy;
        }


        if (type instanceof Enum) {
            Enum enumTy = (Enum)type;
            EnumType dwarfEnum = (EnumType)put(
                type, owner.createEnum(enumTy.getName())
            );

            dwarfEnum.setSize(enumTy.getLength());

            for (String name : enumTy.getNames()) {
                dwarfEnum.addValue(name, enumTy.getValue(name));
            }
            return dwarfEnum;
        }

        if (type instanceof FunctionDefinition) {
            FunctionDefinition funcTy = (FunctionDefinition)type;
            FunctionType dwarfFuncTy  = (FunctionType)put(type,
                owner.createFunctionType(funcTy.getName())
            );
            dwarfFuncTy.setReturnType(addType(funcTy.getReturnType()));
            for (ParameterDefinition arg : funcTy.getArguments()) {
                dwarfFuncTy.addParameter(addType(arg.getDataType()));
            }
            return dwarfFuncTy;
        }

        if (type instanceof Pointer) {
            Pointer ptr = (Pointer)type;
            DataType underlyingType = ptr.getDataType();

            if (underlyingType == null || VoidDataType.isVoidDataType(underlyingType)) {
                return put(type, owner.createVoidType().getPointerTo());
            }
            return put(type, addType(underlyingType).getPointerTo());
        }

        Msg.warn(null, String.format(
            "Unsupported type: %s (%s)", type.getClass().getName(),
            type.getName()
        ));

        return put(type,
            owner.createVoidType().getPointerTo()
        );
    }
}
