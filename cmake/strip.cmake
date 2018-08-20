execute_process(COMMAND
  ${CMAKE_STRIP} --discard-all --discard-locals --strip-all --strip-unneeded ${TARGET_FILE})
