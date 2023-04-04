# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/WireWhale_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/WireWhale_autogen.dir/ParseCache.txt"
  "WireWhale_autogen"
  )
endif()
