// copyright (c) 2019-2021 hors<horsicq@gmail.com>
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

#define X_ALIGN_DOWN(x,align)     ((x)&~(align-1))
#define X_ALIGN_UP(x,align)       (((x)&(align-1))?X_ALIGN_DOWN(x,align)+align:x)

#ifdef Q_OS_WIN
struct S_CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
};

struct S_THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    S_CLIENT_ID             ClientId;
    KAFFINITY               AffinityMask;
    LONG                    Priority;
    LONG                    BasePriority;
};

struct S_PROCESS_BASIC_INFORMATION
{
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

typedef NTSTATUS (NTAPI *pfnNtQueryInformationThread)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
        );

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );
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
        // TODO more
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
    // TODO HANDLE -> (void *)
    static bool setPrivilege(QString sName,bool bEnable);
    static bool setDebugPrivilege(bool bEnable);
    static qint64 getProcessIDByHandle(HANDLE hProcess);
    static qint64 getThreadIDByHandle(HANDLE hThread);
    static qint64 getRegionAllocationSize(HANDLE hProcess, qint64 nRegionBase);
    static qint64 getRegionAllocationBase(HANDLE hProcess, qint64 nAddress);
    static qint64 getRegionBase(HANDLE hProcess, qint64 nAddress);
    static qint64 getRegionSize(HANDLE hProcess, qint64 nAddress);
    static MEMORY_FLAGS dwordToFlags(quint32 nValue);
    static MEMORY_FLAGS getMemoryFlags(HANDLE hProcess,qint64 nAddress);
    static QString getFileNameByHandle(HANDLE hHandle);
    static QString convertNtToDosPath(QString sNtPath);
    static qint64 getTEBAddress(HANDLE hThread);
    static qint64 getPEBAddress(HANDLE hProcess);
#endif
    static void *openProcess(qint64 nProcessID);
    static void closeProcess(void *hProcess);
    static bool isProcessReadable(qint64 nProcessID);
    static bool readData(void *hProcess,qint64 nAddress,char *pBuffer,qint32 nBufferSize); // TODO Remove, use read_array
    static bool writeData(void *hProcess,qint64 nAddress,char *pBuffer,qint32 nBufferSize); // TODO Remove, use write_array
    static quint8 read_uint8(void *hProcess,qint64 nAddress);
    static quint16 read_uint16(void *hProcess,qint64 nAddress);
    static quint32 read_uint32(void *hProcess,qint64 nAddress);
    static quint64 read_uint64(void *hProcess,qint64 nAddress);
    static void write_uint8(void *hProcess,qint64 nAddress,quint8 nValue);
    static void write_uint16(void *hProcess,qint64 nAddress,quint16 nValue);
    static void write_uint32(void *hProcess,qint64 nAddress,quint32 nValue);
    static void write_uint64(void *hProcess,qint64 nAddress,quint64 nValue);
    static qint64 read_array(void *hProcess,qint64 nAddress,char *pData,qint64 nSize);
    static qint64 write_array(void *hProcess,qint64 nAddress,char *pData,qint64 nSize);
    static QByteArray read_array(void *hProcess,qint64 nAddress,qint32 nSize);
    static QString read_ansiString(void *hProcess,qint64 nAddress,qint64 nMaxSize=256);
    static QString read_unicodeString(void *hProcess,qint64 nAddress,qint64 nMaxSize=256); // TODO endian ??
    static QList<MEMORY_REGION> getMemoryRegionsList(void *hProcess,qint64 nAddress,qint64 nSize);
    static MEMORY_REGION getMemoryRegion(void *hProcess,qint64 nAddress);
    static bool isAddressInMemoryRegion(MEMORY_REGION *pMemoryRegion,qint64 nAddress);
    static PROCESS_INFO getInfoByProcessID(qint64 nProcessID);
};

#endif // XPROCESS_H
