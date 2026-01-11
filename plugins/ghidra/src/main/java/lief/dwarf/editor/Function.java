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
import java.util.List;

public class Function extends lief.Base {
    public record Range (long start, long end)
    {}

    public static class Parameter extends lief.Base {
        @Override
        protected native void destroy();

        private Parameter(long impl) {
            super(impl);
        }
    }

    public static class LexicalBlock extends lief.Base {
        @Override
        protected native void destroy();

        public native LexicalBlock addBlock(long start, long end);

        public native LexicalBlock addBlock(List<Range> ranges);

        public native LexicalBlock addDescription(String desc);

        public native LexicalBlock addName(String name);

        private LexicalBlock(long impl) {
            super(impl);
        }
    }

    public static class Label extends lief.Base {
        @Override
        protected native void destroy();

        private Label(long impl) {
            super(impl);
        }
    }

    @Override
    protected native void destroy();

    private Function(long impl) {
        super(impl);
    }

    public native Function setAddress(long addr);

    public native Function setLowHigh(long low, long high);

    public native Function setRanges(List<Range> ranges);

    public native Function setExternal();

    public native Function setReturnType(Type ty);

    public native Parameter addParameter(String name, Type type);

    public native Variable createStackVariable(String name);

    public native LexicalBlock addLexicalBlock(long start, long end);

    public native Label addLabel(long addr, String label);

    public native Function addDescription(String desc);
};
