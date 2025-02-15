target_sources(pyLIEF PRIVATE
  pyLoadConfiguration.cpp
  pyEnclaveConfiguration.cpp
  pyEnclaveImport.cpp
  pyVolatileMetadata.cpp
)

add_subdirectory(CHPEMetadata)
add_subdirectory(DynamicRelocation)
