/* Copyright (c) 2019-2023 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef XPROCESS_H
#define XPROCESS_H

#include <limits>  // Ubuntu 22.04
#include <QtEndian>
#ifdef Q_OS_WIN
#include <Windows.h>
#include <psapi.h>
#include <winternl.h>
#include <Tlhelp32.h>
#include <DbgHelp.h>
#endif
#ifdef Q_OS_LINUX
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <QDirIterator>
#endif
#ifdef Q_OS_MACOS
#include <libproc.h>
#include <mach-o/dyld_images.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/proc_info.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <QDirIterator>
#endif
#ifdef QT_GUI_LIB
#include <QMessageBox>
#endif

#include "xbinary.h"
#include "xiodevice.h"

#ifdef Q_OS_WIN
typedef DWORD X_ID;
typedef HANDLE X_HANDLE;
typedef HANDLE X_HANDLE_IO;
typedef HANDLE X_HANDLE_MQ;
#endif

#ifdef Q_OS_MACOS
typedef quint32 X_ID;
typedef task_t X_HANDLE;
typedef task_t X_HANDLE_IO;
typedef task_t X_HANDLE_MQ;
#endif

#ifdef Q_OS_LINUX
typedef quint32 X_ID;
typedef void *X_HANDLE;
typedef void *X_HANDLE_IO;
typedef void *X_HANDLE_MQ;
#endif

#ifdef Q_OS_WIN
struct S_CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
};

struct S_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    S_CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

struct S_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

struct S_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
};

struct S_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    S_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
};

struct my_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    UINT_PTR ObjectPointer;
    UINT_PTR UniqueProcessId;
    UINT_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct S_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct S_SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    S_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

typedef NTSTATUS(NTAPI *pfnNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                     PULONG ReturnLength);

typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
                                                      ULONG ProcessInformationLength, PULONG ReturnLength);

typedef NTSTATUS(NTAPI *pfnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength,
                                                     PULONG ReturnLength);

#endif

class XProcess : public XIODevice {
    Q_OBJECT

public:
    struct HANDLEID {
        X_ID nID;
        X_HANDLE hHandle;
    };

    struct MEMORY_FLAGS {
        bool bRead;
        bool bWrite;
        bool bExecute;
#ifdef Q_OS_WIN
        bool bGuard;
        bool bCopy;
#endif
#ifdef Q_OS_LINUX
        bool bShare;
        bool bPrivate;
#endif
#ifdef Q_OS_MACOS
        bool bShare;
        bool bReserved;
#endif
    };

    struct MEMORY_REGION {
        XADDR nAddress;
        quint64 nSize;
        MEMORY_FLAGS mf;
#ifdef Q_OS_WIN
        quint64 nAllocationBase;
        MEMORY_FLAGS mfAllocation;
        quint32 nState;
        quint32 nType;
#endif
#ifdef Q_OS_LINUX
        qint64 nOffset;
        QString sDevice;
        qint64 nFile;
        QString sFileName;
#endif
    };

    struct PROCESS_INFO {
        QString sName;
        //        qint64 nParentID;
        X_ID nID;
        QString sFilePath;
        quint64 nImageAddress;
        quint64 nImageSize;
    };

    struct THREAD_INFO {
        qint64 nID;
        qint64 nProcessID;
    };

    struct MODULE {
        quint64 nAddress;
        quint64 nSize;
        QString sName;
        QString sFileName;
    };

#ifdef Q_OS_WIN
    struct WINSYSHANDLE {
        quint16 nProcessID;
        quint16 nCreatorBackTraceIndex;
        quint16 nHandle;
        quint8 nObjectTypeNumber;
        quint8 nFlags;
        quint64 nObjectAddress;
        quint32 nAccess;
    };
#endif

    explicit XProcess(QObject *pParent = nullptr);
    XProcess(X_ID nProcessID, XADDR nAddress, quint64 nSize, QObject *pParent = nullptr);
    XProcess(XADDR nAddress, quint64 nSize, X_HANDLE hHandle, QObject *pParent = nullptr);
    virtual bool open(OpenMode mode);
    virtual void close();

protected:
    virtual qint64 readData(char *pData, qint64 nMaxSize);
    virtual qint64 writeData(const char *pData, qint64 nMaxSize);

public:
    static QList<PROCESS_INFO> getProcessesList(bool bShowAll = false);
    static QList<THREAD_INFO> getThreadsList(qint64 nProcessID);
    static bool setPrivilege(const QString &sName, bool bEnable);
    static bool setDebugPrivilege(bool bEnable);
    static bool isRoot();
#ifdef QT_GUI_LIB
    static bool isRoot(QWidget *pWidget);
#endif
#ifdef Q_OS_WIN
    static qint64 getProcessIDByHandle(X_HANDLE hProcess);
    static qint64 getThreadIDByHandle(X_HANDLE hThread);
    static qint64 getRegionAllocationSize(X_HANDLE hProcess, qint64 nRegionBase);
    static qint64 getRegionAllocationBase(X_HANDLE hProcess, qint64 nAddress);
    static qint64 getRegionBase(X_HANDLE hProcess, qint64 nAddress);
    static qint64 getRegionSize(X_HANDLE hProcess, qint64 nAddress);
    static MEMORY_FLAGS protectToFlags(quint32 nValue);
    static MEMORY_FLAGS getMemoryFlags(X_HANDLE hProcess, qint64 nAddress);
    static QString getFileNameByHandle(X_HANDLE hHandle);
    static QString convertNtToDosPath(const QString &sNtPath);
    static qint64 getTEBAddress(qint64 nThreadID);
    static qint64 getTEBAddress(X_HANDLE hThread);
    static qint64 getPEBAddress(qint64 nProcessID);
    static qint64 getPEBAddress(X_HANDLE hProcess);
    static QList<qint64> getTEBAddresses(qint64 nProcessID);
    static QList<WINSYSHANDLE> getOpenHandles(qint64 nProcessID = -1);
    static QList<WINSYSHANDLE> getOpenHandlesEx(qint64 nProcessID = -1);
    static quint64 getSystemEPROCESSAddress();
    static QString getLastErrorAsString();
    static void getCallStack(X_HANDLE hProcess, X_HANDLE hThread);
#endif
    static X_HANDLE openProcess(X_ID nProcessID);  // TODO move to Windows
    static X_HANDLE_MQ openMemoryQuery(X_ID nProcessID);
    static X_HANDLE_IO openMemoryIO(X_ID nProcessID);
    static void closeProcess(X_HANDLE hProcess);  // TODO move to Windows
    static void closeMemoryQuery(X_HANDLE_MQ hProcess);
    static void closeMemoryIO(X_HANDLE_IO hProcess);
    static void *openThread(qint64 nThreadID);
    static void closeThread(void *hThread);
    static bool isProcessReadable(qint64 nProcessID);
    static quint8 read_uint8(X_HANDLE_IO hProcess, quint64 nAddress);
    static quint16 read_uint16(X_HANDLE_IO hProcess, quint64 nAddress, bool bIsBigEndian = false);
    static quint32 read_uint32(X_HANDLE_IO hProcess, quint64 nAddress, bool bIsBigEndian = false);
    static quint64 read_uint64(X_HANDLE_IO hProcess, quint64 nAddress, bool bIsBigEndian = false);
    static void write_uint8(X_HANDLE_IO hProcess, quint64 nAddress, quint8 nValue);
    static void write_uint16(X_HANDLE_IO hProcess, quint64 nAddress, quint16 nValue, bool bIsBigEndian = false);
    static void write_uint32(X_HANDLE_IO hProcess, quint64 nAddress, quint32 nValue, bool bIsBigEndian = false);
    static void write_uint64(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nValue, bool bIsBigEndian = false);
    static quint64 read_array(X_HANDLE_IO hProcess, quint64 nAddress, char *pData, quint64 nSize);
    static quint64 write_array(X_HANDLE_IO hProcess, quint64 nAddress, char *pData, quint64 nSize);
    static QByteArray read_array(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nSize);
    static QString read_ansiString(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize = 256);
    static QString read_unicodeString(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize = 256);  // TODO endian ??
    static QString read_utf8String(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize = 256);
    static QList<MEMORY_REGION> getMemoryRegionsList_Handle(X_HANDLE_MQ hProcess, XADDR nAddress, quint64 nSize);
    static QList<MEMORY_REGION> getMemoryRegionsList_Id(X_ID nProcessID, XADDR nAddress, quint64 nSize);
    static MEMORY_REGION getMemoryRegion_Handle(X_HANDLE_MQ hProcess, XADDR nAddress);
    static MEMORY_REGION getMemoryRegion_Id(X_ID nProcessID, XADDR nAddress);
    static PROCESS_INFO getInfoByProcessID(X_ID nProcessID);  // TODO rename to getProcessInfoById
                                                              //    static THREAD_INFO getInfoByThreadID(qint64 nThreadID);
    static QList<qint64> getThreadIDsList(X_ID nProcessID);
    static XBinary::OSINFO getOsInfo();
    static QList<MODULE> getModulesList(qint64 nProcessID);
    static MODULE getModuleByAddress(QList<MODULE> *pListModules, quint64 nAddress);
    static MODULE getModuleByFileName(QList<MODULE> *pListModules, QString sFileName);
    static bool isAddressInMemoryRegion(MEMORY_REGION *pMemoryRegion, XADDR nAddress);
    static MEMORY_REGION getMemoryRegionByAddress(QList<MEMORY_REGION> *pListMemoryRegions, quint64 nAddress);
    static QString memoryFlagsToString(MEMORY_FLAGS mf);

    static quint32 getMemoryRegionsListHash_Id(X_ID nProcessID);
    static quint32 getMemoryRegionsListHash_Handle(X_HANDLE_MQ hProcess);
    static quint32 getModulesListHash(X_ID nProcessID);
    static quint32 getThreadsListHash(X_ID nProcessID);
    static quint32 getProcessesListHash();

    static QString memoryRegionToString(MEMORY_REGION memoryRegion);

private:
    const qint64 N_BUFFER_SIZE = 0x1000;
    X_ID g_nProcessID;
    X_HANDLE g_hProcess;
};

#endif  // XPROCESS_H
