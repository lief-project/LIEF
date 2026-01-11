/***
 * Copyright 2022 - 2026 R. Thomas
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
package lief.ghidra.core;

import ghidra.util.Msg;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.Architecture;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

public class NativeBridge {

    public static volatile boolean isInitialized = false;

    public static final String JNI_HELPER_BASENAME = "lief-jni";
    public static final String LIEF_BASENAME = "LIEF";
    public static final String DEFAULT_MODULE_NAME = "LIEF";

    private String moduleName;

    public static String getLibraryExtension() {
        return Platform.CURRENT_PLATFORM.getLibraryExtension();
    }

    public static String getLibraryPrefix() {
        if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.LINUX ||
            Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X ||
            Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.FREE_BSD)
        {
            return "lib";
        }

        if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS)
        {
            return "";
        }
        return "";
    }

    public String getPlatformLibraryName(String name, boolean withPrefix) {
        if (withPrefix) {
            return getLibraryPrefix() + name + getLibraryExtension();
        }
        return name + getLibraryExtension();
    }

    public NativeBridge(String moduleName) {
        this.moduleName = moduleName;
    }

    public ResourceFile getJNIHelper() throws FileNotFoundException {
        String suffix = new String("-");
        OperatingSystem system = Platform.CURRENT_PLATFORM.getOperatingSystem();
        Architecture arch = Platform.CURRENT_PLATFORM.getArchitecture();
        if (system == OperatingSystem.MAC_OS_X) {
            suffix += "darwin-";
        }
        else if (system == OperatingSystem.WINDOWS) {
            suffix += "windows-";
        }
        else if (system == OperatingSystem.LINUX) {
            suffix += "linux-";
        }

        if (arch == Architecture.ARM_64) {
            suffix += "arm64";
        }
        else if (arch == Architecture.X86_64) {
            suffix += "x86_64";
        }

        return Application.getModuleDataFile(moduleName, getPlatformLibraryName(
            JNI_HELPER_BASENAME + suffix, /*withPrefix=*/false)
        );
    }

    public ResourceFile getLIEF() throws FileNotFoundException {
        String liefLibraryName = getPlatformLibraryName(LIEF_BASENAME, /*withPrefix=*/true);
        List<String> candidates;
        try {
            return Application.getModuleDataFile(moduleName, liefLibraryName);
        } catch (FileNotFoundException e) {
            File moduleDir = Application.getModuleRootDir(moduleName).getFile(/*copyIfNeeded*/false);
            File parentModuleDir = moduleDir.getParentFile();

            candidates = Arrays.asList(
                moduleDir.getPath() + File.separatorChar + liefLibraryName,
                parentModuleDir.getPath() + File.separatorChar + liefLibraryName
            );

            for (String candidate : candidates) {
                File candidateFile = new File(candidate);
                if (candidateFile.isFile()) {
                    return new ResourceFile(candidateFile);
                }
            }
        }

        throw new FileNotFoundException(String.format(
            "Couldn't find '%s' in the following path:\n- %s", liefLibraryName,
            String.join("\n- ", candidates)
        ).toString());
    }

    public synchronized void loadLibraries() {
        if (isInitialized) {
            return;
        }

        try {
            System.load(getLIEF().getAbsolutePath());
            System.load(getJNIHelper().getAbsolutePath());
        } catch (FileNotFoundException e) {
            Msg.showError(NativeBridge.class, null, "File not found", "Couldn't find the native library", e);
            return;
        } catch (UnsatisfiedLinkError e) {
            Msg.showError(NativeBridge.class, null, "Loading Error", "Couldn't load native library", e);
            return;
        }
        isInitialized = true;
    }

    public static void init(String moduleName) {
        NativeBridge bridge = new NativeBridge(moduleName);
        bridge.loadLibraries();
    }

    public static void init() {
        init(DEFAULT_MODULE_NAME);
    }

    public static boolean isLoaded() {
        return isInitialized;
    }

}
