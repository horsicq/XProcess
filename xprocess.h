/* Copyright (c) 2019-2022 hors<horsicq@gmail.com>
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

#include <QObject>
#include <QtEndian>
#ifdef Q_OS_WIN
#include <Windows.h>
#include <winternl.h>
#include <Tlhelp32.h>
#include <psapi.h>
#endif
#ifdef Q_OS_LINUX
#include <QDirIterator>
#endif

#include "xbinary.h"

#ifdef Q_OS_WIN
struct S_CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
};

struct S_THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    S_CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

struct S_PROCESS_BASIC_INFORMATION
{
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

struct S_SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
};

struct S_SYSTEM_HANDLE_INFORMATION
{
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

struct S_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct S_SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    S_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
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

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

#endif

class XProcess : public QObject
{
    Q_OBJECT

public:

    struct HANDLEID
    {
        void *hHandle;
        qint64 nID;
    };

    struct PROCESS_INFO
    {
        QString sName;
        //        qint64 nParentID;
        qint64 nID;
        QString sFilePath;
        qint64 nImageAddress;
        qint64 nImageSize;
    };

    struct MODULE
    {
        qint64 nAddress;
        qint64 nSize;
        QString sName;
        QString sFileName;
    };

#ifdef Q_OS_WIN
    struct WINSYSHANDLE
    {
        quint16 nProcessID;
        quint16 nCreatorBackTraceIndex;
        quint16 nHandle;
        quint8 nObjectTypeNumber;
        quint8 nFlags;
        quint64 nObjectAddress;
        quint32 nAccess;
    };
#endif

    explicit XProcess(QObject *parent=nullptr);
    static QList<PROCESS_INFO> getProcessesList();
    static bool setPrivilege(QString sName,bool bEnable);
    static bool setDebugPrivilege(bool bEnable);
#ifdef Q_OS_WIN
    static qint64 getProcessIDByHandle(void *hProcess);
    static qint64 getThreadIDByHandle(void *hThread);
    static qint64 getRegionAllocationSize(void *hProcess,qint64 nRegionBase);
    static qint64 getRegionAllocationBase(void *hProcess,qint64 nAddress);
    static qint64 getRegionBase(void *hProcess,qint64 nAddress);
    static qint64 getRegionSize(void *hProcess,qint64 nAddress);
    static XBinary::MEMORY_FLAGS protectToFlags(quint32 nValue);
    static XBinary::MEMORY_FLAGS getMemoryFlags(void *hProcess,qint64 nAddress);
    static QString getFileNameByHandle(void *hHandle);
    static QString convertNtToDosPath(QString sNtPath);
    static qint64 getTEBAddress(qint64 nThreadID);
    static qint64 getTEBAddress(void *hThread);
    static qint64 getPEBAddress(qint64 nProcessID);
    static qint64 getPEBAddress(void *hProcess);
    static QList<qint64> getTEBAddresses(qint64 nProcessID);
    static QList<WINSYSHANDLE> getOpenHandles(qint64 nProcessID=-1);
    static QList<WINSYSHANDLE> getOpenHandlesEx(qint64 nProcessID=-1);
    static quint64 getSystemEPROCESSAddress();
    static QString getLastErrorAsString();
#endif
    static void *openProcess(qint64 nProcessID);
    static void *openMemoryMapQuery(qint64 nProcessID);
    static void closeProcess(void *hProcess);
    static void closeMemoryMapQuery(void *hProcess);
    static void *openThread(qint64 nThreadID);
    static void closeThread(void *hThread);
    static bool isProcessReadable(qint64 nProcessID);
    static quint8 read_uint8(void *hProcess,qint64 nAddress);
    static quint16 read_uint16(void *hProcess,qint64 nAddress,bool bIsBigEndian=false);
    static quint32 read_uint32(void *hProcess,qint64 nAddress,bool bIsBigEndian=false);
    static quint64 read_uint64(void *hProcess,qint64 nAddress,bool bIsBigEndian=false);
    static void write_uint8(void *hProcess,qint64 nAddress,quint8 nValue);
    static void write_uint16(void *hProcess,qint64 nAddress,quint16 nValue,bool bIsBigEndian=false);
    static void write_uint32(void *hProcess,qint64 nAddress,quint32 nValue,bool bIsBigEndian=false);
    static void write_uint64(void *hProcess,qint64 nAddress,quint64 nValue,bool bIsBigEndian=false);
    static qint64 read_array(void *hProcess,qint64 nAddress,char *pData,qint64 nSize);
    static qint64 write_array(void *hProcess,qint64 nAddress,char *pData,qint64 nSize);
    static QByteArray read_array(void *hProcess,qint64 nAddress,qint32 nSize);
    static QString read_ansiString(void *hProcess,qint64 nAddress,qint64 nMaxSize=256);
    static QString read_unicodeString(void *hProcess,qint64 nAddress,qint64 nMaxSize=256); // TODO endian ??
    static QList<XBinary::MEMORY_REGION> getMemoryRegionsList(void *hProcess,quint64 nAddress,quint64 nSize);
    static QList<XBinary::MEMORY_REGION> getMemoryRegionsList(qint64 nProcessID,quint64 nAddress,quint64 nSize);
    static QList<XBinary::MEMORY_REGION> getMemoryRegionsList(HANDLEID handleID,quint64 nAddress,quint64 nSize);
    static XBinary::MEMORY_REGION getMemoryRegion(void *hProcess,qint64 nAddress);
    static XBinary::MEMORY_REGION getMemoryRegion(qint64 nProcessID,qint64 nAddress);
    static XBinary::MEMORY_REGION getMemoryRegion(HANDLEID handleID,qint64 nAddress);
    static PROCESS_INFO getInfoByProcessID(qint64 nProcessID);
    static QList<qint64> getThreadIDsList(qint64 nProcessID);
    static XBinary::OSINFO getOsInfo();
    static QList<MODULE> getModulesList(qint64 nProcessID);
};

#endif // XPROCESS_H
