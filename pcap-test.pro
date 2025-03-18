QT -= gui
CONFIG += c++11 console
CONFIG -= app_bundle

SOURCES += main.cpp

# libpcap 라이브러리 추가
LIBS += -lpcap

# Include 디렉토리 설정 (필요시)
# INCLUDEPATH += /usr/include/pcap
