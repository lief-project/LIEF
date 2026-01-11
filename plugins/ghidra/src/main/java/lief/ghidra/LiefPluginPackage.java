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
package lief.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.util.Msg;
import resources.ResourceManager;

public class LiefPluginPackage extends PluginPackage {
    public static final String NAME = "LIEF";

    public LiefPluginPackage() {
        super(NAME, ResourceManager.loadImage("images/LIEF/logo.png"),
              "Plugins based on LIEF", FEATURE_PRIORITY);
        Msg.info(LiefPluginPackage.class, String.format(
            "%s initialized", LiefPluginPackage.class.getName()
        ));
    }
}
