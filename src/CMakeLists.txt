set (PROJECT_NAME dnssniffer)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})



file(GLOB HDRS "*.h" "${CMAKE_SYSTEM_NAME}/*.h")
file(GLOB SRCS "*.cpp" "${CMAKE_SYSTEM_NAME}/*.cpp")


add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})

# libs to link

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	target_link_libraries (${PROJECT_NAME} zdnsparser c dl "${OS_LIBS}" pcap )
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	target_link_libraries (${PROJECT_NAME} ${OS_LIBS} ${PCAP_LIB} zdnsparser)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  target_link_libraries (${PROJECT_NAME} zdnsparser "${OS_LIBS}" pcap )
endif()
