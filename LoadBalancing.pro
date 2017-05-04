QT += core network concurrent
QT -= gui

TARGET = LoadBalancing
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    common/dhcpserverinfo.cpp \
    common/sshconsole.cpp \
    loadbalancing.cpp \
    network/pcapanalyze.cpp \
    network/genericpcapcapture.cpp \
    network/pcapreader.cpp \
    common/tcpserver.cpp

HEADERS += \
    common/dhcpserverinfo.h \
    common/sshconsole.h \
    loadbalancing.h \
    network/pcapanalyze.h \
    network/genericpcapcapture.h \
    network/pcapreader.h \
    common/tcpserver.h

INSTALL_PREFIX = $$OUT_PWD/..

INCLUDEPATH += $$INSTALL_PREFIX/usr/local/include/
LIBS += $$INSTALL_PREFIX/usr/local/lib/libEncoderCommonLibrary.a
PRE_TARGETDEPS += $$INSTALL_PREFIX/usr/local/lib/libEncoderCommonLibrary.a

LIBS += -lpcap
LIBS += -lcrypt -lssh -lx264


