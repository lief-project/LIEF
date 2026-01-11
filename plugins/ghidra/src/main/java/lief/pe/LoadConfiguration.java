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
import java.util.OptionalInt;
import java.util.OptionalLong;

public class LoadConfiguration extends lief.Base {
    public enum GuardFlags {
        IMAGE_GUARD_CF_INSTRUMENTED(0x100),
        IMAGE_GUARD_CFW_INSTRUMENTED(0x200),
        IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT(0x400),
        IMAGE_GUARD_SECURITY_COOKIE_UNUSED(0x800),
        IMAGE_GUARD_PROTECT_DELAYLOAD_IAT(0x1000),
        IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION(0x2000),
        IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT(0x4000),
        IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION(0x8000),
        IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT(0x10000),
        IMAGE_GUARD_RF_INSTRUMENTED(0x00020000),
        IMAGE_GUARD_RF_ENABLE(0x00040000),
        IMAGE_GUARD_RF_STRICT(0x00080000),
        IMAGE_GUARD_RETPOLINE_PRESENT(0x00100000);

        private final int value;

        GuardFlags(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    @Override
    protected native void destroy();

    private LoadConfiguration(long impl) {
        super(impl);
    }

    public native int getSize();

    public native int getTimedatestamp();

    public native short getMajorVersion();

    public native short getMinorVersion();

    public native int getGlobalFlagsClear();

    public native int getGlobalFlagsSet();

    public native int getCriticalSectionDefaultTimeout();

    public native long getDeCommitFreeBlockThreshold();

    public native long getDeCommitTotalFreeThreshold();

    public native long getLockPrefixTable();

    public native long getMaximumAllocationSize();

    public native long getVirtualMemoryThreshold();

    public native long getProcessAffinityMask();

    public native int getProcessHeapFlags();

    public native short getCsdVersion();

    public native short getDependentLoadFlags();

    public native long getEditList();

    public native long getSecurityCookie();

    public native OptionalLong getSEHandlerTable();

    public native OptionalLong getSEHandlerCount();

    public native OptionalLong getGuardCfcCheckFunctionPointer();

    public native OptionalLong getGuardCfDispatchFunctionPointer();

    public native OptionalLong getGuardCfFunctionTable();

    public native OptionalLong getGuardCfFunctionCount();

    public native OptionalInt getGuardFlags();

    public native Optional<CodeIntegrity> getCodeIntegrity();

    public native OptionalLong getGuardAddressTakenIatEntryTable();

    public native OptionalLong getGuardAddressTakenIatEntryCount();

    public native OptionalLong getGuardLongJumpTargetTable();

    public native OptionalLong getGuardLongJumpTargetCount();

    public native OptionalLong getDynamicValueRelocTable();

    public native OptionalLong getCHPEMetadataPointer();

    public native Optional<CHPEMetadata> getCHPEMetadata();

    public native OptionalLong getGuardRfFailureRoutine();

    public native OptionalLong getGuardRfFailureRoutineFunctionPointer();

    public native OptionalInt getDynamicValueRelocTableOffset();

    public native OptionalInt getDynamicValueRelocTableSection();

    public native OptionalInt getReserved2();

    public native OptionalLong getGuardRfVerifyStackPointerFunctionPointer();

    public native OptionalInt getHotPatchTableOffset();

    public native OptionalInt getReserved3();

    public native OptionalLong getEnclaveConfigurationPointer();

    public native OptionalLong getVolatileMetadataPointer();

    public native OptionalLong getGuardEHContinuationTable();

    public native OptionalLong getGuardEHContinuationCount();

    public native OptionalLong getGuardXfgCheckFunctionPointer();

    public native OptionalLong getGuardXfgDispatchFunctionPointer();

    public native OptionalLong getGuardXfgTableDispatchFunctionPointer();

    public native OptionalLong getCastGuardOsDeterminedFailureMode();

    public native OptionalLong getGuardMemcpyFunctionPointer();

    public native OptionalLong getUmaFunctionPointers();
}
