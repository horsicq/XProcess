// copyright (c) 2019 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#ifndef XPROCESS_H
#define XPROCESS_H

#include <QObject>
#ifdef Q_OS_WIN
#include <Windows.h>
#include <winternl.h>
#include <Tlhelp32.h>
#include <psapi.h>
#endif
#ifdef Q_OS_LINUX
#include <QDirIterator>
#endif

class XProcess : public QObject
{
    Q_OBJECT
public:
    struct PROCESS_INFO
    {
        QString sName;
        //        qint64 nParentID;
        qint64 nID;
        QString sFilePath;
        qint64 nImageAddress;
        qint64 nImageSize;
    };
    struct MEMORY_FLAGS
    {
        bool bRead;
        bool bWrite;
        bool bExecute;
    };
    struct MEMORY_REGION
    {
        qint64 nAddress;
        qint64 nSize;
        MEMORY_FLAGS mf;
    };

    explicit XProcess(QObject *parent=nullptr);
    static QList<PROCESS_INFO> getProcessesList();
#ifdef Q_OS_WIN
    static bool setPrivilege(QString sName,bool bEnable);
    static qint64 getProcessIDByHandle(HANDLE hProcess);
    static qint64 getThreadIDByHandle(HANDLE hThread);
    static qint64 getImageSize(HANDLE hProcess,qint64 nImageBase);
    static MEMORY_FLAGS getMemoryFlags(HANDLE hProcess,qint64 nAddress);
    static QString getFileNameByHandle(HANDLE hHandle);
    static QString convertNtToDosPath(QString sNtPath);
    static bool readData(HANDLE hProcess,qint64 nAddress,char *pBuffer,qint32 nBufferSize);
    static bool writeData(HANDLE hProcess,qint64 nAddress,char *pBuffer,qint32 nBufferSize);
    static quint8 read_uint8(HANDLE hProcess,qint64 nAddress);
    static quint16 read_uint16(HANDLE hProcess,qint64 nAddress);
    static quint32 read_uint32(HANDLE hProcess,qint64 nAddress);
    static quint64 read_uint64(HANDLE hProcess,qint64 nAddress);
    static void write_uint32(HANDLE hProcess,qint64 nAddress,quint32 nValue);
    static void write_uint64(HANDLE hProcess,qint64 nAddress,quint64 nValue);
    static QByteArray read_array(HANDLE hProcess,qint64 nAddress,qint32 nSize);
    static QString read_ansiString(HANDLE hProcess,qint64 nAddress,qint64 nMaxSize=256);
    static QString read_unicodeString(HANDLE hProcess,qint64 nAddress,qint64 nMaxSize=256); // TODO endian ??
#endif
    static PROCESS_INFO getInfoByProcessID(qint64 nProcessID);
};

#endif // XPROCESS_H
