INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \ 
    $$PWD/xprocess.h \
    $$PWD/xprocessdevice.h

SOURCES += \ 
    $$PWD/xprocess.cpp \
    $$PWD/xprocessdevice.cpp

win32-msvc* {
    LIBS += Advapi32.lib
}

win32-g++ {
    LIBS += libadvapi32
    LIBS += libpsapi
}
