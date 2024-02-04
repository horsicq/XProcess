include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xbinary.cmake)

set(XPROCESS_SOURCES
    ${XBINARY_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xprocess.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xprocessdevice.cpp
)
