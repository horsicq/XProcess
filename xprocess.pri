INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \ 
    $$PWD/xprocess.h \
    $$PWD/xprocessdevice.h

SOURCES += \ 
    $$PWD/xprocess.cpp \
    $$PWD/xprocessdevice.cpp

!contains(XCONFIG, xbinary) {
    XCONFIG += xbinary
    include($$PWD/../Formats/xbinary.pri)
}
# TODO cmake !!!
win32-msvc* {
    LIBS += Advapi32.lib
}

win32-g++ {
    LIBS += libadvapi32
    LIBS += libpsapi
}
