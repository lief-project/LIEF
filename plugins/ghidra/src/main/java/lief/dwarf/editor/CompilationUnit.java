/* Copyright 2022 - 2026 R. Thomas
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
package lief.dwarf.editor;

public class CompilationUnit extends lief.Base {
    @Override
    protected native void destroy();

    private CompilationUnit(long impl) {
        super(impl);
    }

    public native void setProducer(String producer);

    public native Function createFunction(String name);

    public native Variable createVariable(String name);

    public native Type createGenericType(String name);

    public native EnumType createEnum(String name);

    public native TypeDef createTypedef(String name, Type type);

    public native StructType createStructure(String name, StructType.Type kind);

    public StructType createStructure(String name) {
        return createStructure(name, StructType.Type.STRUCT);
    }

    public native BaseType
        createBaseType(String name, int size, BaseType.Encoding encoding);

    public BaseType createBaseType(String name, int size) {
        return createBaseType(name, size, BaseType.Encoding.NONE);
    }

    public native FunctionType createFunctionType(String name);

    public PointerType createPointerType(Type ty) {
        return ty.getPointerTo();
    }

    public native Type createVoidType();

    public native ArrayType createArray(String name, Type ty, int count);
};
