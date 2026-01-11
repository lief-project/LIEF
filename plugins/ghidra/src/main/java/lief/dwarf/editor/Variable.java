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

public class Variable extends lief.Base {
    @Override
    protected native void destroy();

    private Variable(long impl) {
        super(impl);
    }

    public native Variable setAddr(long addr);

    public native Variable setStackOffset(long offset);

    public native Variable setExternal();

    public native Variable setType(Type ty);

    public native Variable addDescription(String desc);
};
