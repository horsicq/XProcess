include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED XBINARY_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xbinary.cmake)
    set(XPROCESS_SOURCES ${XPROCESS_SOURCES} ${XBINARY_SOURCES})
endif()

set(XPROCESS_SOURCES
    ${XPROCESS_SOURCES}
    ${XBINARY_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xprocess.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xprocess.h
    ${CMAKE_CURRENT_LIST_DIR}/xprocessdevice.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xprocessdevice.h
)
