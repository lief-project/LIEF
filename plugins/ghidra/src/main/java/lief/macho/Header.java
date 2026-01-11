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

public class Header extends lief.Base {
    @Override
    protected native void destroy();

    private Header(long impl) {
        super(impl);
    }

    public enum FileType {
        UNKNOWN,
        OBJECT,
        EXECUTE,
        FVMLIB,
        CORE,
        PRELOAD,
        DYLIB,
        DYLINKER,
        BUNDLE,
        DYLIB_STUB,
        DSYM,
        KEXT_BUNDLE
    }

    public enum CpuType {
        ANY(-1),
        X86(7),
        X86_64(7 | CpuType.ABI64),
        MIPS(8),
        MC98000(10),
        HPPA(11),
        ARM(12),
        ARM64(12 | CpuType.ABI64),
        MC88000(13),
        SPARC(14),
        I860(15),
        ALPHA(16),
        POWERPC(18),
        POWERPC64(18 | CpuType.ABI64);

        public final int value;

        public static final int ABI64 = 0x01000000;

        CpuType(int value) {
            this.value = value;
        }
    }
    public native CpuType getCpuType();

    public native FileType getFileType();

    public native int getCpuSubType();
}
