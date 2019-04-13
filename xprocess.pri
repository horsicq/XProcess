INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \ 
    $$PWD/xprocess.h \
    $$PWD/xprocessdevice.h

SOURCES += \ 
    $$PWD/xprocess.cpp \
    $$PWD/xprocessdevice.cpp

win32 {
    LIBS += Advapi32.lib
}
