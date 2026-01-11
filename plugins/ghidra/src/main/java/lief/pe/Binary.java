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
package lief.pe;

import java.util.Optional;

public class Binary extends lief.generic.Binary {
    private Binary(long impl) {
        super(impl);
    }

    public static native Binary parse(String path);

    public native Optional<LoadConfiguration> getLoadConfiguration();

    public native Optional<DataDirectory> getLoadConfigurationDir();

    public native ExceptionsIterator getExceptions();

    public static class ExceptionsIterator extends lief.Iterator<ExceptionInfo>
                                           implements Iterable<ExceptionInfo>
    {
        public ExceptionsIterator(long impl) {
            super(impl);
        }

        @Override
        public ExceptionsIterator iterator() {
            return this;
        }

        @Override
        protected native void destroy();

        @Override
        public native boolean hasNext();

        @Override
        public native ExceptionInfo next();
    }

}
