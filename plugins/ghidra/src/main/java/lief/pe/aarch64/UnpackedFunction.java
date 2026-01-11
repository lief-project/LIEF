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
package lief.pe.aarch64;

import lief.pe.RuntimeFunctionAArch64;

public class UnpackedFunction extends RuntimeFunctionAArch64 {
    @Override
    protected native void destroy();

    private UnpackedFunction(long impl) {
        super(impl);
    }
    public native int getXdataRVA();

    public native boolean isExtended();

    public native long getUnwindCodeOffset();

    public native long getEpilogScopesOffset();

    public native long getNbEpilogScopes();

    public native long getExceptionHandlerOffset();

    public native byte[] getUnwindCode();

}
