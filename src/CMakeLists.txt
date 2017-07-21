set (PROJECT_NAME dnssniffer)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})



file(GLOB HDRS "*.h" "${CMAKE_SYSTEM_NAME}/*.h")
file(GLOB SRCS "*.cpp" "${CMAKE_SYSTEM_NAME}/*.cpp")

add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})

