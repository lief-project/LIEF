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
package lief.elf;

public class Binary extends lief.generic.Binary {
    private Binary(long impl) {
        super(impl);
    }

    public static class RelocationsIterator extends lief.Iterator<Relocation>
                                            implements Iterable<Relocation>
    {
        public RelocationsIterator(long impl) {
            super(impl);
        }

        @Override
        public RelocationsIterator iterator() {
            return this;
        }

        @Override
        protected native void destroy();

        @Override
        public native boolean hasNext();

        @Override
        public native Relocation next();
    }

    public static native Binary parse(String path);

    public native RelocationsIterator getRelocations();
}
