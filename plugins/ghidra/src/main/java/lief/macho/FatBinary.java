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
package lief.macho;

public class FatBinary extends lief.Base implements Iterable<Binary> {
    @Override
    protected native void destroy();

    private FatBinary(long impl) {
        super(impl);
    }

    public static native FatBinary parse(String path);

    @Override
    public native Iterator iterator();

    public static class Iterator extends lief.Iterator<Binary> {
        public Iterator(long impl) {
            super(impl);
        }

        @Override
        protected native void destroy();

        @Override
        public native boolean hasNext();

        @Override
        public native Binary next();
    }
}
