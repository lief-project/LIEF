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

public class CHPEMetadataARM64 extends CHPEMetadata {
    @Override
    protected native void destroy();

    private CHPEMetadataARM64(long impl) {
        super(impl);
    }

    public native int getCodeMap();

    public native int getCodeMapCount();

    public native int getCodeRangesToEntrypoints();

    public native int getRedirectionMetadata();

    public native int getOsArm64xDispatchCallNoRedirect();

    public native int getOsArm64xDispatchRet();

    public native int getOsArm64xDispatchCall();

    public native int getOsArm64xDispatchICall();

    public native int getOsArm64xDispatchIcallCfg();

    public native int getAlternateEntryPoint();

    public native int getAuxiliaryIAT();

    public native int getCodeRangesToEntryPointsCount();

    public native int getRedirectionMetadataCount();

    public native int getX64InformationFunctionPointer();

    public native int setX64InformationFunctionPointer();

    public native int getExtraRfeTable();

    public native int getExtraRfeTableSize();

    public native int getOsArm64xDispatchFptr();

    public native int getAuxiliaryIATCopy();

    public native int getAuxiliaryDelayImport();

    public native int getAuxiliaryDelayImportCopy();

    public native int getBitfieldInfo();

}
