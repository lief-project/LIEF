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
package lief.ghidra.plugins.analyzers;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;
import lief.ghidra.core.NativeBridge;

public abstract class LIEFAbstractAnalyzer extends AbstractAnalyzer {
    public LIEFAbstractAnalyzer(String name, String description, AnalyzerType type) {
        super(name, description, type);
        NativeBridge.init();
    }

    protected boolean isELF(Program program) {
      return ElfLoader.ELF_NAME.equals(program.getExecutableFormat());
    }
}
