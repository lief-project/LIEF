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

public class StructType extends Type {
    private StructType(long impl) {
        super(impl);
    }

    public enum Type {
        CLASS,
        STRUCT,
        UNION
    }

    public static class Member extends lief.Base {
        @Override
        protected native void destroy();

        private Member(long impl) {
            super(impl);
        }
    }

    public native StructType setSize(int size);

    public native Member addMember(
        String name, lief.dwarf.editor.Type type, long offset);

    public Member addMember(String name, lief.dwarf.editor.Type type) {
        return addMember(name, type, /*offset=*/-1);
    }
};
