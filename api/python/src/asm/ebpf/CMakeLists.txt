target_sources(pyLIEF PRIVATE
  init.cpp
  pyInstruction.cpp
  pyOpcode.cpp
  pyOperand.cpp
  pyRegister.cpp
)

add_subdirectory(operands)
