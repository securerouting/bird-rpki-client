set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")

project(bird-rpki-client)

cmake_minimum_required(VERSION 2.6)

exec_program(net-snmp-config
             ARGS    --base-cflags
             OUTPUT_VARIABLE  NETSNMPCFLAGS)

string(STRIP "${NETSNMPCFLAGS}" ${NETSNMPCFLAGS})
	   
exec_program(net-snmp-config
             ARGS    --agent-libs
             OUTPUT_VARIABLE  NETSNMPLIBS)

string(STRIP "${NETSNMPLIBS}" ${NETSNMPLIBS})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NETSNMPCFLAGS}")

include_directories(${RTRLIB_INCLUDE} ${INCLUDE_DIRECTORIES})

add_executable(bird-rpki-client bird-rpki-client.c cli.c config.c rpkiRtrPrefixOriginTable_data_get.c rpkiRtrPrefixOriginTable_data_access.c rpkiRtrPrefixOriginTable.c rpkiRtrCacheServerTable_interface.c rpkiRtrCacheServerTable.c rpkiRtrPrefixOriginTable_data_set.c rpkiRtrCacheServerTable_data_access.c rpkiRtrPrefixOriginTable_interface.c rpkiRtrCacheServerTable_data_get.c rpkiRtr_subagent.c rpkiRtrCacheServerTable_data_set.c)

target_link_libraries(bird-rpki-client rtr "${NETSNMPLIBS}")



