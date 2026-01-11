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
package lief;

public class Utils {
    public record Version (long major, long minor, long patch, long id) {}

    /**
     * Whether it is an extended version of LIEF
     */
    public static native boolean isExtended();

    /**
     * Return details about the extended version
     */
    public static native String getExtendedVersionInfo();

    /**
     * Return version info about the extended version
     */
    public static native Version getExtendedVersion();

    public static native Version getVersion();

    private Utils() {
        // Can't be instantiated
    }
};
