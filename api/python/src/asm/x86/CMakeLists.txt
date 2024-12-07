target_sources(pyLIEF PRIVATE
  init.cpp
  pyInstruction.cpp
  pyOpcode.cpp
  pyRegister.cpp
  pyOperand.cpp
)

add_subdirectory(operands)
