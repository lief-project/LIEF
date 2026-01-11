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

public class EnumType extends Type {
    private EnumType(long impl) {
        super(impl);
    }

    public static class Value extends lief.Base {
        private Value(long impl) {
            super(impl);
        }

        @Override
        protected native void destroy();
    }

    public native EnumType setSize(long size);

    public native Value addValue(String name, long value);
};

