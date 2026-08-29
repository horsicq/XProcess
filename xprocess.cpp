/* Copyright (c) 2019-2026 hors<horsicq@gmail.com>
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
#include "xprocess.h"

#include <QVector>
#include <limits>
#include <new>

#ifdef Q_OS_MACOS
#include <mach/mach.h>

namespace {
bool getDarwinMemoryRegion(task_t hProcess, mach_vm_address_t nAddress, mach_vm_address_t *pRegionAddress, mach_vm_size_t *pRegionSize, vm_prot_t *pProtection)
{
    mach_vm_address_t nRegionAddress = nAddress;
    mach_vm_size_t nRegionSize = 0;
    natural_t nDepth = 1024;

#if defined(VM_REGION_SUBMAP_SHORT_INFO_COUNT_64)
    vm_region_submap_short_info_data_64_t regionInfo = {};
    mach_msg_type_number_t nInfoCount = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
#else
    vm_region_submap_info_data_64_t regionInfo = {};
    mach_msg_type_number_t nInfoCount = VM_REGION_SUBMAP_INFO_COUNT_64;
#endif

    const kern_return_t result = mach_vm_region_recurse(hProcess, &nRegionAddress, &nRegionSize, &nDepth, (vm_region_recurse_info_t)&regionInfo, &nInfoCount);

    if ((result != KERN_SUCCESS) || (nRegionAddress > nAddress) || ((nAddress - nRegionAddress) >= nRegionSize)) {
        return false;
    }

    *pRegionAddress = nRegionAddress;
    *pRegionSize = nRegionSize;
    *pProtection = regionInfo.protection;

    return true;
}
}  // namespace
#endif

#ifdef Q_OS_LINUX
qint32 _openLargeFile(QString sFileName, qint32 nFlags)
{
    qint32 nResult = open64(sFileName.toUtf8().data(), nFlags);

    return nResult;
}
#endif
#ifdef Q_OS_LINUX
bool _closeLargeFile(qint32 nFD)
{
    bool bResult = false;

    bResult = (close(nFD) != -1);

    return bResult;
}
#endif

#ifdef Q_OS_LINUX
qint64 _readLargeFile(qint32 nFD, quint64 nOffset, char *pData, quint32 nDataSize)
{
    if ((nFD < 0) || ((nDataSize > 0) && !pData) || (nOffset > (quint64)(std::numeric_limits<qint64>::max)())) return -1;
    return (qint64)pread64(nFD, pData, (size_t)nDataSize, (off64_t)nOffset);
}
#endif

#ifdef Q_OS_LINUX
qint64 _writeLargeFile(qint32 nFD, quint64 nOffset, const char *pData, quint32 nDataSize)
{
    if ((nFD < 0) || ((nDataSize > 0) && !pData) || (nOffset > (quint64)(std::numeric_limits<qint64>::max)())) return -1;
    return (qint64)pwrite64(nFD, pData, (size_t)nDataSize, (off64_t)nOffset);
}
#endif

XProcess::XProcess(QObject *pParent) : XIODevice(pParent)
{
    g_nProcessID = 0;
    g_hProcess = 0;
}

XProcess::XProcess(X_ID nProcessID, XADDR nAddress, quint64 nSize, QObject *pParent) : XIODevice(pParent)
{
    g_nProcessID = nProcessID;
    g_hProcess = 0;

    setInitLocation(nAddress);
    setSize(nSize);
}

XProcess::XProcess(XADDR nAddress, quint64 nSize, X_HANDLE_IO hHandle, QObject *pParent) : XIODevice(pParent)
{
    g_nProcessID = 0;
    g_hProcess = hHandle;

    setInitLocation(nAddress);
    setSize(nSize);
}

XProcess::~XProcess()
{
    close();
}

bool XProcess::open(OpenMode mode)
{
    bool bResult = false;

    const qint64 nDeviceSize = size();
    if (((mode != ReadOnly) && (mode != WriteOnly) && (mode != ReadWrite)) || (nDeviceSize <= 0) ||
        (getInitLocation() > ((std::numeric_limits<quint64>::max)() - (quint64)(nDeviceSize - 1)))) {
        return false;
    }
#ifdef Q_OS_WIN
    if ((getInitLocation() + (quint64)nDeviceSize - 1) > (quint64)(std::numeric_limits<quintptr>::max)()) return false;
#elif defined(Q_OS_LINUX)
    if ((getInitLocation() + (quint64)nDeviceSize - 1) > (quint64)(std::numeric_limits<qint64>::max)()) return false;
#endif

    if (isOpen() || (g_nProcessID && g_hProcess)) close();

    if (g_nProcessID) {
#ifdef Q_OS_WIN
        quint32 nFlag = 0;

        if (mode == ReadOnly) {
            nFlag = PROCESS_VM_READ;
        } else if (mode == WriteOnly) {
            nFlag = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        } else {
            nFlag = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        }

        g_hProcess = OpenProcess(nFlag, 0, (DWORD)g_nProcessID);  // TODO Errors

        bResult = (g_hProcess != nullptr);
#endif
#ifdef Q_OS_LINUX
        qint32 nFlag = 0;

        if (mode == ReadOnly) {
            nFlag = O_RDONLY;
        } else if (mode == WriteOnly) {
            nFlag = O_WRONLY;
        } else if (mode == ReadWrite) {
            nFlag = O_RDWR;
        }

        QString sMapMemory = QString("/proc/%1/mem").arg(g_nProcessID);
        qint64 nFD = _openLargeFile(sMapMemory, nFlag);

        if (nFD != -1) {
            g_hProcess = nFD;

            bResult = true;
        }
#endif
#ifdef Q_OS_MACOS
        mach_port_name_t task = 0;
        kern_return_t error = task_for_pid(mach_task_self(), g_nProcessID, &task);

        if (error == KERN_SUCCESS) {
            g_hProcess = task;
            bResult = true;
        }
#endif
    } else if (g_hProcess) {
        bResult = true;
    }

    if (!bResult || !XIODevice::open(mode) || !XIODevice::seek(0)) {
        close();
        return false;
    }

    return true;
}

void XProcess::close()
{
    if (isOpen()) XIODevice::close();

    if (g_nProcessID && g_hProcess) {
#ifdef Q_OS_WIN
        CloseHandle(g_hProcess);
#endif
#ifdef Q_OS_LINUX
        _closeLargeFile((qint64)g_hProcess);
#endif
#ifdef Q_OS_MACOS
        mach_port_deallocate(mach_task_self(), g_hProcess);
#endif
        g_hProcess = 0;
    }
}

qint64 XProcess::readData(char *pData, qint64 nMaxSize)
{
    const qint64 nPosition = pos();
    if (!isOpen() || !isReadable() || !g_hProcess || (nMaxSize < 0) || ((nMaxSize > 0) && !pData) || (nPosition < 0) || (nPosition > size())) {
        return -1;
    }

    nMaxSize = qMin(nMaxSize, size() - nPosition);
    if (!nMaxSize) return 0;

    const quint64 nStartOffset = getInitLocation() + (quint64)nPosition;
    qint64 nResult = 0;
    qint64 nCurrentPosition = nPosition;
    char *pCurrentData = pData;

    while (nResult < nMaxSize) {
        qint64 nDelta = N_BUFFER_SIZE - (nCurrentPosition % N_BUFFER_SIZE);
        nDelta = qMin(nDelta, nMaxSize - nResult);
        const quint64 nTransferred = read_array(g_hProcess, getInitLocation() + (quint64)nCurrentPosition, pCurrentData, (quint64)nDelta);
        if (!nTransferred) {
            if (!nResult) return -1;
            break;
        }
        if (nTransferred > (quint64)nDelta) return nResult ? nResult : -1;

        nCurrentPosition += (qint64)nTransferred;
        pCurrentData += nTransferred;
        nResult += (qint64)nTransferred;
        if (nTransferred != (quint64)nDelta) break;
    }

    if (nResult) emit readDataSignal(nStartOffset, pData, nResult);

#ifdef QT_DEBUG
    QString sErrorString = errorString();
    if ((sErrorString != "") && (sErrorString != "Unknown error")) {
        qDebug("%s", sErrorString.toLatin1().data());
    }
#endif

    return nResult;
}

qint64 XProcess::writeData(const char *pData, qint64 nMaxSize)
{
    const qint64 nPosition = pos();
    if (!isOpen() || !isWritable() || !g_hProcess || (nMaxSize < 0) || ((nMaxSize > 0) && !pData) || (nPosition < 0) || (nPosition > size())) {
        return -1;
    }

    nMaxSize = qMin(nMaxSize, size() - nPosition);
    if (!nMaxSize) return 0;
    if ((quint64)nMaxSize > (quint64)(std::numeric_limits<size_t>::max)()) return -1;

    char *pDataCopy = new (std::nothrow) char[(size_t)nMaxSize];
    if (!pDataCopy) return -1;
    XBinary::_copyMemory(pDataCopy, (char *)pData, nMaxSize);

    const quint64 nStartOffset = getInitLocation() + (quint64)nPosition;
    qint64 nResult = 0;
    qint64 nCurrentPosition = nPosition;
    char *pCurrentData = pDataCopy;

    while (nResult < nMaxSize) {
        qint64 nDelta = N_BUFFER_SIZE - (nCurrentPosition % N_BUFFER_SIZE);
        nDelta = qMin(nDelta, nMaxSize - nResult);
        const quint64 nTransferred = write_array(g_hProcess, getInitLocation() + (quint64)nCurrentPosition, pCurrentData, (quint64)nDelta);
        if (!nTransferred) {
            if (!nResult) nResult = -1;
            break;
        }
        if (nTransferred > (quint64)nDelta) {
            if (!nResult) nResult = -1;
            break;
        }

        nCurrentPosition += (qint64)nTransferred;
        pCurrentData += nTransferred;
        nResult += (qint64)nTransferred;
        if (nTransferred != (quint64)nDelta) break;
    }

    if (nResult > 0) emit writeDataSignal(nStartOffset, pDataCopy, nResult);
    delete[] pDataCopy;

#ifdef QT_DEBUG
    QString sErrorString = errorString();
    if ((sErrorString != "") && (sErrorString != "Unknown error")) {
        qDebug("%s", sErrorString.toLatin1().data());
    }
#endif

    return nResult;
}

QList<XProcess::PROCESS_INFO> XProcess::getProcessesList(bool bShowAll, XBinary::PDSTRUCT *pPdStruct)
{
    QList<PROCESS_INFO> listResult;

    XBinary::PDSTRUCT pdStructEmpty = XBinary::createPdStruct();

    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }

#ifdef Q_OS_WIN
    HANDLE hProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcesses != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32 = {};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hProcesses, &pe32)) {
            do {
                PROCESS_INFO processInfo = getInfoByProcessID(pe32.th32ProcessID);

                bool bSuccess = false;

                if ((processInfo.nID == 0) && (bShowAll)) {
                    processInfo.nID = pe32.th32ProcessID;
                    processInfo.sName = QString::fromWCharArray(pe32.szExeFile);
                }

                if ((processInfo.nID) || (bShowAll)) {
                    bSuccess = true;
                }

                if (bSuccess) {
                    listResult.append(processInfo);
                }
            } while (Process32NextW(hProcesses, &pe32) && (!(pPdStruct->bIsStop)));
        }

        CloseHandle(hProcesses);
    }

#endif
#ifdef Q_OS_LINUX
    QDirIterator it("/proc");

    while (it.hasNext()) {
        QString sRecord = it.next();

        QFileInfo fi(sRecord);

        if (fi.isDir()) {
            qint64 nPID = fi.baseName().toInt();

            PROCESS_INFO processInfo = getInfoByProcessID(nPID);

            bool bSuccess = false;

            if (processInfo.nID) {
                bSuccess = true;
            } else if (bShowAll) {
                processInfo.nID = nPID;
                processInfo.sName = "";

                bSuccess = true;
            }

            if (bSuccess) {
                listResult.append(processInfo);
            }
        }
    }
#endif
#ifdef Q_OS_MACOS
    size_t nProcBuffSize = 0;
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int st = sysctl(name, 4, NULL, &nProcBuffSize, NULL, 0);

    if (nProcBuffSize) {
        char *pData = new char[nProcBuffSize];

        st = sysctl(name, 4, pData, &nProcBuffSize, NULL, 0);

        qint32 nNumberOfProcesses = nProcBuffSize / sizeof(kinfo_proc);

        kinfo_proc *pKinfo_proc = (kinfo_proc *)pData;

        for (qint32 i = 0; i < nNumberOfProcesses; i++) {
            qint64 nPID = pKinfo_proc[i].kp_proc.p_pid;

            PROCESS_INFO processInfo = getInfoByProcessID(nPID);

            listResult.append(processInfo);
        }

        delete[] pData;
    }
#endif
    return listResult;
}

QList<XProcess::THREAD_INFO> XProcess::getThreadsList(qint64 nProcessID)
{
    QList<THREAD_INFO> listResult;

#ifdef Q_OS_WIN
    HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, (DWORD)nProcessID);

    if (hThreads != INVALID_HANDLE_VALUE) {
        THREADENTRY32 thread = {};
        thread.dwSize = sizeof(tagTHREADENTRY32);

        if (Thread32First(hThreads, &thread)) {
            do {
                if (thread.th32OwnerProcessID == nProcessID) {
                    THREAD_INFO threadInfo = {};

                    threadInfo.nID = thread.th32ThreadID;
                    threadInfo.nProcessID = thread.th32OwnerProcessID;

                    listResult.append(threadInfo);
                }
            } while (Thread32Next(hThreads, &thread));
        }

        CloseHandle(hThreads);
    }
#endif
#ifdef Q_OS_LINUX
    QDirIterator it(QString("/proc/%1/task").arg(nProcessID));

    while (it.hasNext()) {
        QString sRecord = it.next();

        QFileInfo fi(sRecord);

        if (fi.isDir()) {
            qint64 nID = fi.baseName().toLongLong();

            if (nID > 0) {
                THREAD_INFO threadInfo = {};

                threadInfo.nID = nID;
                threadInfo.nProcessID = nProcessID;

                listResult.append(threadInfo);
            }
        }
    }
#endif

    return listResult;
}

bool XProcess::setDebugPrivilege(bool bEnable)
{
    return setPrivilege("SeDebugPrivilege", bEnable);
}

bool XProcess::isRoot()
{
    bool bResult = false;

#ifdef Q_OS_WIN
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation = {};
        DWORD dwSize = 0;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            if (elevation.TokenIsElevated) {
                bResult = true;
            }
        }

        CloseHandle(hToken);
    }
#endif

#ifdef Q_OS_LINUX
    if (geteuid() == 0) {
        bResult = true;
    }
#endif
    // TODO Check macOS

    return bResult;
}
#ifdef QT_GUI_LIB
bool XProcess::isRoot(QWidget *pWidget)
{
    bool bResult = isRoot();

    if (!bResult) {
        QMessageBox::critical(pWidget, tr("Error"), tr("Please run the program as an administrator"));
        // QMessageBox::critical(pWidget,tr("Error"),tr("please run this program as root"));
    }

    return bResult;
}
#endif
bool XProcess::setPrivilege(const QString &sName, bool bEnable)
{
    bool bResult = true;
#ifdef Q_OS_WIN
    bResult = false;
    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID SeValue;

        if (LookupPrivilegeValueA(nullptr, sName.toLatin1().data(), &SeValue)) {
            TOKEN_PRIVILEGES tp = {};

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = SeValue;
            tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);

            bResult = true;
        }

        CloseHandle(hToken);
    }
#else
    Q_UNUSED(sName)
    Q_UNUSED(bEnable)
#endif
    return bResult;
}

QList<XProcess::MEMORY_REGION> XProcess::getMemoryRegionsList_Handle(X_HANDLE_MQ hProcess, XADDR nAddress, quint64 nSize)
{
    QList<MEMORY_REGION> listResult;
#ifdef Q_OS_WIN
    for (quint64 nCurrentAddress = nAddress; nCurrentAddress < nAddress + nSize;) {
        nCurrentAddress = S_ALIGN_DOWN(nCurrentAddress, 0x1000);

        MEMORY_BASIC_INFORMATION mbi = {};

        if (VirtualQueryEx(hProcess, (LPCVOID)nCurrentAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            MEMORY_REGION memoryRegion = {};

            memoryRegion.nType = mbi.Type;

            if (memoryRegion.nType) {
                memoryRegion.nAddress = (XADDR)mbi.BaseAddress;
                memoryRegion.nSize = (qint64)mbi.RegionSize;
                memoryRegion.mf = protectToFlags(mbi.Protect);
                memoryRegion.nAllocationBase = (XADDR)mbi.AllocationBase;
                memoryRegion.mfAllocation = protectToFlags(mbi.AllocationProtect);
                memoryRegion.nState = mbi.State;

                listResult.append(memoryRegion);
            }

            nCurrentAddress += (XADDR)mbi.RegionSize;
        } else {
            break;
        }
    }
#endif
#ifdef Q_OS_LINUX
    QFile *pFile = static_cast<QFile *>(hProcess);

    if (pFile) {
        pFile->seek(0);
        QByteArray baData = pFile->readAll();

        QTextStream inStream(baData, QIODevice::ReadOnly);

        while (!inStream.atEnd()) {
            QString sRecord = inStream.readLine();

            QString sAddress = sRecord.section(" ", 0, 0);
            QString sFlags = sRecord.section(" ", 1, 1);
            QString sOffset = sRecord.section(" ", 2, 2);
            QString sDevice = sRecord.section(" ", 3, 3);
            QString sFileNumber = sRecord.section(" ", 4, 4);
            QString sPathName = sRecord.section(" ", 5, -1).trimmed();

            MEMORY_REGION memoryRegion = {};

            memoryRegion.nAddress = sAddress.section("-", 0, 0).toULongLong(0, 16);
            memoryRegion.nSize = sAddress.section("-", 1, 1).toULongLong(0, 16) - memoryRegion.nAddress;

            if ((memoryRegion.nAddress >= nAddress) && (nAddress + nSize >= memoryRegion.nAddress + memoryRegion.nSize)) {
                memoryRegion.mf.bExecute = sFlags.contains("x");
                memoryRegion.mf.bRead = sFlags.contains("r");
                memoryRegion.mf.bWrite = sFlags.contains("w");
                memoryRegion.mf.bPrivate = sFlags.contains("p");
                memoryRegion.mf.bShare = sFlags.contains("s");
                memoryRegion.nOffset = sOffset.toLongLong(0, 16);
                memoryRegion.sDevice = sDevice;
                memoryRegion.nFile = sFileNumber.toLongLong(0, 10);
                memoryRegion.sFileName = sPathName;

                listResult.append(memoryRegion);
            }
        }
    }
#endif
#ifdef Q_OS_MAC
    for (XADDR nCurrentAddress = nAddress; nCurrentAddress < nAddress + nSize;) {
        mach_vm_address_t _nAddress = nCurrentAddress;
        mach_vm_size_t _nSize = 0;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_t info = {};
        mach_port_t object_name = 0;

        if (mach_vm_region(hProcess, &_nAddress, &_nSize, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object_name) == KERN_SUCCESS) {
            MEMORY_REGION memoryRegion = {};

            memoryRegion.nAddress = _nAddress;
            memoryRegion.nSize = _nSize;
            memoryRegion.mf.bShare = info.shared;
            memoryRegion.mf.bReserved = info.reserved;

            listResult.append(memoryRegion);

            if (_nSize == 0) {
                break;
            }

            nCurrentAddress = _nAddress + _nSize;
        } else {
            break;
        }
    }
#endif
    return listResult;
}

QList<XProcess::MEMORY_REGION> XProcess::getMemoryRegionsList_Id(X_ID nProcessID, XADDR nAddress, quint64 nSize)
{
    QList<MEMORY_REGION> listResult;

    X_HANDLE_MQ pProcess = openMemoryQuery(nProcessID);  // TODO OpenMemoryQuery QFile for linux

    if (pProcess) {
        listResult = getMemoryRegionsList_Handle(pProcess, nAddress, nSize);

        closeMemoryQuery(pProcess);  // TODO CloseMemoryQuery
    }

    return listResult;
}

XProcess::MEMORY_REGION XProcess::getMemoryRegion_Handle(X_HANDLE_MQ hProcess, XADDR nAddress)
{
    // TODO LINUX
    MEMORY_REGION result = {};
#ifdef Q_OS_WIN
    // #ifndef Q_OS_WIN64
    //     MEMORY_BASIC_INFORMATION32 mbi={};
    // #else
    //     MEMORY_BASIC_INFORMATION64 mbi={};
    // #endif
    MEMORY_BASIC_INFORMATION mbi = {};

    nAddress = S_ALIGN_DOWN(nAddress, 0x1000);

    if (VirtualQueryEx(hProcess, (LPCVOID)nAddress, (MEMORY_BASIC_INFORMATION *)&mbi, sizeof(mbi)) == sizeof(mbi)) {
        result.nAddress = (XADDR)mbi.BaseAddress;
        result.nSize = (qint64)mbi.RegionSize;
        result.mf = protectToFlags(mbi.Protect);
    }

//    // TODO Check
//    if(result.nSize>0x10000)
//    {
//        result.nSize=0x10000;
//    }
#endif
#ifdef Q_OS_LINUX
    QList<MEMORY_REGION> listRecords = getMemoryRegionsList_Handle(hProcess, 0, 0xFFFFFFFFFFFFFFFF);

    qint32 nNumberOfRecords = listRecords.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((nAddress >= listRecords.at(i).nAddress) && (nAddress < listRecords.at(i).nAddress + listRecords.at(i).nSize)) {
            result = listRecords.at(i);

            break;
        }
    }
#endif
#ifdef Q_OS_MAC
    // task_t task=(task_t)hProcess;

    // mach_vm_region_info_64();
    //  TODO
#endif

    return result;
}

XProcess::MEMORY_REGION XProcess::getMemoryRegion_Id(X_ID nProcessID, XADDR nAddress)
{
    MEMORY_REGION result = {};

    X_HANDLE_MQ pProcess = openMemoryQuery(nProcessID);

    if (pProcess) {
        result = getMemoryRegion_Handle(pProcess, nAddress);

        closeMemoryQuery(pProcess);
    }

    return result;
}

XProcess::PROCESS_INFO XProcess::getInfoByProcessID(X_ID nProcessID)
{
    PROCESS_INFO result = {0};
#ifdef Q_OS_WIN
    if (nProcessID) {
        HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)nProcessID);

        if (hModule != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me32 = {};
            me32.dwSize = sizeof(MODULEENTRY32W);

            if (Module32FirstW(hModule, &me32)) {
                if ((qint64)me32.modBaseAddr) {
                    result.nID = nProcessID;
                    result.nImageAddress = (qint64)me32.modBaseAddr;
                    result.nImageSize = (qint64)me32.modBaseSize;
                    result.sFilePath = QString::fromWCharArray(me32.szExePath);
                    result.sName = QString::fromWCharArray(me32.szModule);
                }
            }

            CloseHandle(hModule);
        }
    }
#endif
#ifdef Q_OS_LINUX
    if (nProcessID) {
        // TODO argument
        QFile file;
        file.setFileName(QString("/proc/%1/cmdline").arg(nProcessID));

        if (file.open(QIODevice::ReadOnly)) {
            QByteArray baData = file.readAll();
            QList<QByteArray> list = baData.split(0);

            if (list.count()) {
                QString sFilePath = list.at(0).data();

                if (sFilePath != "") {
                    QFileInfo fi(sFilePath);

                    result.sFilePath = sFilePath;

                    if (fi.exists()) {
                        result.nID = nProcessID;
                        result.sName = fi.baseName();
                    }
                }
            }

            file.close();
        }
    }
#endif
#ifdef Q_OS_MACOS
    if (nProcessID) {
        result.nID = nProcessID;

        char szName[PROC_PIDPATHINFO_MAXSIZE] = {};
        char szPath[PROC_PIDPATHINFO_MAXSIZE] = {};

        proc_name(nProcessID, szName, PROC_PIDPATHINFO_MAXSIZE);
        proc_pidpath(nProcessID, szPath, PROC_PIDPATHINFO_MAXSIZE);

        result.sName = szName;
        result.sFilePath = szPath;
    }
#endif
    return result;
}

// XProcess::THREAD_INFO XProcess::getInfoByThreadID(qint64 nThreadID)
//{
//     THREAD_INFO result={0};
// #ifdef Q_OS_WIN
//     if(nThreadID)
//     {
//         HANDLE hModule=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,(DWORD)nThreadID);

//        if(hModule!=INVALID_HANDLE_VALUE)
//        {
//            THREADENTRY32 me32={};
//            me32.dwSize=sizeof(THREADENTRY32);

//            if(Thread32First(hModule,&me32))
//            {
//                result.nID=me32.th32ThreadID;
//                result.nProcessID=me32.th32OwnerProcessID;
//            }

//            CloseHandle(hModule);
//        }
//    }
// #endif
// #ifdef Q_OS_LINUX
//    // TODO
// #endif
//    return result;
//}
QList<qint64> XProcess::getThreadIDsList(X_ID nProcessID)
{
    QList<qint64> listResult;

#ifdef Q_OS_WIN
    HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, (DWORD)nProcessID);

    if (hThreads != INVALID_HANDLE_VALUE) {
        tagTHREADENTRY32 thread = {};
        thread.dwSize = sizeof(tagTHREADENTRY32);

        if (Thread32First(hThreads, &thread)) {
            do {
                if (thread.th32OwnerProcessID == nProcessID) {
                    listResult.append(thread.th32ThreadID);
                }
            } while (Thread32Next(hThreads, &thread));
        }

        CloseHandle(hThreads);
    }
#else
    Q_UNUSED(nProcessID)
#endif

    return listResult;
}

#ifdef Q_OS_WIN
qint64 XProcess::getRegionAllocationSize(X_HANDLE hProcess, qint64 nRegionBase)
{
    qint64 nResult = 0;

    qint64 _nAddress = nRegionBase;

    while (true) {
        MEMORY_BASIC_INFORMATION mbi = {};

        if (!VirtualQueryEx(hProcess, (LPCVOID)_nAddress, &mbi, sizeof(mbi))) {
            break;
        }

        if ((mbi.RegionSize) && ((qint64)mbi.AllocationBase == nRegionBase)) {
            nResult += mbi.RegionSize;
            _nAddress += mbi.RegionSize;
        } else {
            break;
        }
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionAllocationBase(X_HANDLE hProcess, qint64 nAddress)
{
    qint64 nResult = -1;

    nAddress = S_ALIGN_DOWN(nAddress, 0x1000);

    MEMORY_BASIC_INFORMATION mbi = {};

    if (VirtualQueryEx(hProcess, (LPCVOID)nAddress, &mbi, sizeof(mbi))) {
        nResult = (qint64)mbi.AllocationBase;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionBase(X_HANDLE hProcess, qint64 nAddress)
{
    qint64 nResult = -1;

    nAddress = S_ALIGN_DOWN(nAddress, 0x1000);

    MEMORY_BASIC_INFORMATION mbi = {};

    if (VirtualQueryEx(hProcess, (LPCVOID)nAddress, &mbi, sizeof(mbi))) {
        nResult = (XADDR)mbi.BaseAddress;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionSize(X_HANDLE hProcess, qint64 nAddress)
{
    qint64 nResult = -1;

    nAddress = S_ALIGN_DOWN(nAddress, 0x1000);

    MEMORY_BASIC_INFORMATION mbi = {};

    if (VirtualQueryEx(hProcess, (LPCVOID)nAddress, &mbi, sizeof(mbi))) {
        nResult = (qint64)mbi.RegionSize;
    }

    return nResult;
}

XProcess::MEMORY_FLAGS XProcess::protectToFlags(quint32 nValue)
{
    MEMORY_FLAGS result = {};

    if (nValue & PAGE_GUARD) {
        result.bGuard = true;
    }

    if (nValue & PAGE_READONLY) {
        result.bRead = true;
    } else if (nValue & PAGE_WRITECOPY) {
        result.bWrite = true;
        result.bCopy = true;
    } else if (nValue & PAGE_READWRITE) {
        result.bRead = true;
        result.bWrite = true;
    } else if (nValue & PAGE_EXECUTE) {
        result.bExecute = true;
    } else if (nValue & PAGE_EXECUTE_READ) {
        result.bExecute = true;
        result.bRead = true;
    } else if (nValue & PAGE_EXECUTE_READWRITE) {
        result.bExecute = true;
        result.bRead = true;
        result.bWrite = true;
    } else if (nValue & PAGE_EXECUTE_WRITECOPY) {
        result.bExecute = true;
        result.bWrite = true;
        result.bCopy = true;
    } else if (nValue) {
#ifdef QT_DEBUG
        qDebug("Unknown protectToFlags");
#endif
    }
    // TODO more for Windows !

    return result;
}
#endif
#ifdef Q_OS_WIN
XProcess::MEMORY_FLAGS XProcess::getMemoryFlags(X_HANDLE hProcess, qint64 nAddress)
{
    MEMORY_FLAGS result = {};
    MEMORY_BASIC_INFORMATION mbi = {};

    if (VirtualQueryEx(hProcess, (LPCVOID)nAddress, &mbi, sizeof(mbi))) {
        result = protectToFlags(mbi.Protect);
    }

    return result;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::getFileNameByHandle(X_HANDLE hHandle)
{
    QString sResult;

    HANDLE hFileMapping = CreateFileMappingW(hHandle, nullptr, PAGE_READONLY, 0, GetFileSize(hHandle, nullptr), nullptr);

    if (hFileMapping) {
        void *pMem = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

        if (pMem) {
            WCHAR wszBuffer[1024];

            if (GetMappedFileNameW(GetCurrentProcess(), pMem, wszBuffer, sizeof(wszBuffer))) {
                sResult = QString::fromUtf16(reinterpret_cast<const char16_t *>(wszBuffer));
                sResult = convertNtToDosPath(sResult);
            }

            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMapping);
    }

    return sResult;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::convertNtToDosPath(const QString &sNtPath)
{
    QString sResult = sNtPath;

    qint32 nSize = GetLogicalDriveStringsW(0, 0);

    if (nSize) {
        WCHAR wszNtBuffer[256];

        WCHAR *pwszBuffer = new WCHAR[nSize + 1];

        nSize = GetLogicalDriveStringsW(nSize, pwszBuffer);

        for (qint32 i = 0; i < nSize;) {
            QString sDisk = QString::fromUtf16(reinterpret_cast<const char16_t *>(pwszBuffer + i));
            sDisk = sDisk.remove("\\");

            i += sDisk.size() + 1;

            if (QueryDosDeviceW((WCHAR *)sDisk.utf16(), wszNtBuffer, sizeof(wszNtBuffer))) {
                QString sNt = QString::fromUtf16(reinterpret_cast<const char16_t *>(wszNtBuffer));

                QString _sNtPath = sNtPath;
                _sNtPath.resize(sNt.size());

                if (_sNtPath == sNt) {
                    sResult = sDisk + sNtPath.mid(sNt.size(), -1);

                    break;
                }
            }
        }

        delete[] pwszBuffer;
    }

    return sResult;
}
#endif

X_HANDLE XProcess::openProcess(X_ID nProcessID)
{
    X_HANDLE pResult = 0;
#ifdef Q_OS_WIN
    pResult = (void *)OpenProcess(PROCESS_ALL_ACCESS, 0, nProcessID);
#endif
#ifdef Q_OS_MAC
    kern_return_t error = task_for_pid(mach_task_self(), nProcessID, &pResult);
#ifdef QT_DEBUG
    if (error != KERN_SUCCESS) {
        qDebug("%s", mach_error_string(error));
    }
#endif
#endif
#ifdef Q_OS_LINUX
    Q_UNUSED(nProcessID)
#endif
    return pResult;
}

X_HANDLE_MQ XProcess::openMemoryQuery(X_ID nProcessID)
{
    X_HANDLE_MQ pResult = 0;
#ifdef Q_OS_WIN
    pResult = OpenProcess(PROCESS_ALL_ACCESS, 0, nProcessID);
#endif
#ifdef Q_OS_LINUX
    // TODO _openLargeFile
    QFile *pFile = new QFile;
    pFile->setFileName(QString("/proc/%1/maps").arg(nProcessID));

    if (XBinary::tryToOpen(pFile)) {
        pResult = pFile;
    }
#endif
#ifdef Q_OS_MAC
    task_for_pid(mach_task_self(), nProcessID, &pResult);
#endif
    return pResult;
}

X_HANDLE_IO XProcess::openMemoryIO(X_ID nProcessID)
{
    X_HANDLE_IO pResult = 0;
#ifdef Q_OS_WIN
    pResult = OpenProcess(PROCESS_ALL_ACCESS, 0, nProcessID);
#endif
#ifdef Q_OS_LINUX
    QString sMapMemory = QString("/proc/%1/mem").arg(nProcessID);
    qint64 nFD = _openLargeFile(sMapMemory, O_RDWR);

    if (nFD != -1) {
        pResult = (X_HANDLE_IO)nFD;
    }
#endif
#ifdef Q_OS_MAC
    task_for_pid(mach_task_self(), nProcessID, &pResult);
#endif
    return pResult;
}

void XProcess::closeProcess(X_HANDLE hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle(hProcess);
#else
    Q_UNUSED(hProcess)
#endif
}

void XProcess::closeMemoryQuery(X_HANDLE_MQ hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hProcess);
#endif
#ifdef Q_OS_LINUX
    QFile *pFile = static_cast<QFile *>(hProcess);

    if (pFile) {
        pFile->close();
    }
#endif
}

void XProcess::closeMemoryIO(X_HANDLE_IO hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hProcess);
#endif
#ifdef Q_OS_LINUX
    // TODO _closeLargeFile
    if (hProcess) {
        _closeLargeFile((qint64)hProcess);
    }
#endif
}

void *XProcess::openThread(qint64 nThreadID)
{
    void *pResult = 0;
#ifdef Q_OS_WIN
    pResult = (void *)OpenThread(THREAD_ALL_ACCESS, 0, nThreadID);
#else
    Q_UNUSED(nThreadID)
#endif
    return pResult;
}

void XProcess::closeThread(void *hThread)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hThread);
#else
    Q_UNUSED(hThread)
#endif
}

bool XProcess::isProcessReadable(qint64 nProcessID)
{
    bool bResult = false;

    X_HANDLE_IO pProcessHandle = openMemoryIO(nProcessID);

    if (pProcessHandle) {
        bResult = true;

        closeMemoryIO(pProcessHandle);
    }

    return bResult;
}

quint8 XProcess::read_uint8(X_HANDLE_IO hProcess, quint64 nAddress)
{
    quint8 nResult = 0;

    read_array(hProcess, nAddress, (char *)&nResult, 1);

    return nResult;
}

quint16 XProcess::read_uint16(X_HANDLE_IO hProcess, quint64 nAddress, bool bIsBigEndian)
{
    quint16 nResult = 0;

    read_array(hProcess, nAddress, (char *)&nResult, 2);

    if (bIsBigEndian) {
        nResult = qFromBigEndian(nResult);
    } else {
        nResult = qFromLittleEndian(nResult);
    }

    return nResult;
}

quint32 XProcess::read_uint32(X_HANDLE_IO hProcess, quint64 nAddress, bool bIsBigEndian)
{
    quint32 nResult = 0;

    read_array(hProcess, nAddress, (char *)&nResult, 4);

    if (bIsBigEndian) {
        nResult = qFromBigEndian(nResult);
    } else {
        nResult = qFromLittleEndian(nResult);
    }

    return nResult;
}

quint64 XProcess::read_uint64(X_HANDLE_IO hProcess, quint64 nAddress, bool bIsBigEndian)
{
    quint64 nResult = 0;

    read_array(hProcess, nAddress, (char *)&nResult, 8);

    if (bIsBigEndian) {
        nResult = qFromBigEndian(nResult);
    } else {
        nResult = qFromLittleEndian(nResult);
    }

    return nResult;
}

void XProcess::write_uint8(X_HANDLE_IO hProcess, quint64 nAddress, quint8 nValue)
{
    write_array(hProcess, nAddress, (char *)&nValue, 1);
}

void XProcess::write_uint16(X_HANDLE_IO hProcess, quint64 nAddress, quint16 nValue, bool bIsBigEndian)
{
    if (bIsBigEndian) {
        nValue = qFromBigEndian(nValue);
    } else {
        nValue = qFromLittleEndian(nValue);
    }

    write_array(hProcess, nAddress, (char *)&nValue, 2);
}

void XProcess::write_uint32(X_HANDLE_IO hProcess, quint64 nAddress, quint32 nValue, bool bIsBigEndian)
{
    if (bIsBigEndian) {
        nValue = qFromBigEndian(nValue);
    } else {
        nValue = qFromLittleEndian(nValue);
    }

    write_array(hProcess, nAddress, (char *)&nValue, 4);
}

void XProcess::write_uint64(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nValue, bool bIsBigEndian)
{
    if (bIsBigEndian) {
        nValue = qFromBigEndian(nValue);
    } else {
        nValue = qFromLittleEndian(nValue);
    }

    write_array(hProcess, nAddress, (char *)&nValue, 8);
}

quint64 XProcess::read_array(X_HANDLE_IO hProcess, quint64 nAddress, char *pData, quint64 nSize)
{
    if (!nSize) return 0;
    if (!pData || (nSize > (quint64)(std::numeric_limits<size_t>::max)()) || (nAddress > ((std::numeric_limits<quint64>::max)() - (nSize - 1)))) return 0;

    quint64 nResult = 0;
    while (nResult < nSize) {
        quint64 nChunkSize = nSize - nResult;
#ifdef Q_OS_WIN
        if (!hProcess) break;
        nChunkSize = qMin<quint64>(nChunkSize, (quint64)(std::numeric_limits<SIZE_T>::max)());
        SIZE_T nRead = 0;
        const BOOL bSuccess = ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>((quintptr)(nAddress + nResult)), pData + (size_t)nResult, (SIZE_T)nChunkSize, &nRead);
        if ((!bSuccess && !nRead) || ((quint64)nRead > nChunkSize)) break;
        nChunkSize = (quint64)nRead;
#elif defined(Q_OS_LINUX)
        if (hProcess < 0) break;
        nChunkSize = qMin<quint64>(nChunkSize, (quint64)(std::numeric_limits<quint32>::max)());
        const qint64 nRead = _readLargeFile(hProcess, nAddress + nResult, pData + (size_t)nResult, (quint32)nChunkSize);
        if ((nRead <= 0) || ((quint64)nRead > nChunkSize)) break;
        nChunkSize = (quint64)nRead;
#elif defined(Q_OS_MACOS)
        if (hProcess == MACH_PORT_NULL) break;
        mach_vm_size_t nRead = 0;
        const kern_return_t result =
            mach_vm_read_overwrite(hProcess, (mach_vm_address_t)(nAddress + nResult), (mach_vm_size_t)nChunkSize, (mach_vm_address_t)(pData + (size_t)nResult), &nRead);
        if ((result != KERN_SUCCESS) || !nRead || ((quint64)nRead > nChunkSize)) break;
        nChunkSize = (quint64)nRead;
#else
        break;
#endif
        nResult += nChunkSize;
        if (!nChunkSize) break;
    }

    return nResult;
}

quint64 XProcess::write_array(X_HANDLE_IO hProcess, quint64 nAddress, char *pData, quint64 nSize)
{
    if (!nSize) return 0;
    if (!pData || (nSize > (quint64)(std::numeric_limits<size_t>::max)()) || (nAddress > ((std::numeric_limits<quint64>::max)() - (nSize - 1)))) return 0;

    quint64 nResult = 0;
    while (nResult < nSize) {
        quint64 nChunkSize = nSize - nResult;
#ifdef Q_OS_WIN
        if (!hProcess) break;
        nChunkSize = qMin<quint64>(nChunkSize, (quint64)(std::numeric_limits<SIZE_T>::max)());
        SIZE_T nWritten = 0;
        const BOOL bSuccess =
            WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>((quintptr)(nAddress + nResult)), pData + (size_t)nResult, (SIZE_T)nChunkSize, &nWritten);
        if ((!bSuccess && !nWritten) || ((quint64)nWritten > nChunkSize)) break;
        nChunkSize = (quint64)nWritten;
#elif defined(Q_OS_LINUX)
        if (hProcess < 0) break;
        nChunkSize = qMin<quint64>(nChunkSize, (quint64)(std::numeric_limits<quint32>::max)());
        const qint64 nWritten = _writeLargeFile(hProcess, nAddress + nResult, pData + (size_t)nResult, (quint32)nChunkSize);
        if ((nWritten <= 0) || ((quint64)nWritten > nChunkSize)) break;
        nChunkSize = (quint64)nWritten;
#elif defined(Q_OS_MACOS)
        if (hProcess == MACH_PORT_NULL) break;

        const mach_vm_address_t nCurrentAddress = (mach_vm_address_t)(nAddress + nResult);
        mach_vm_address_t nRegionAddress = 0;
        mach_vm_size_t nRegionSize = 0;
        vm_prot_t nOriginalProtection = VM_PROT_NONE;

        if (!getDarwinMemoryRegion(hProcess, nCurrentAddress, &nRegionAddress, &nRegionSize, &nOriginalProtection)) break;

        const mach_vm_size_t nRegionBytesLeft = nRegionSize - (nCurrentAddress - nRegionAddress);
        nChunkSize = qMin<quint64>(nChunkSize, (quint64)nRegionBytesLeft);
        nChunkSize = qMin<quint64>(nChunkSize, (quint64)(std::numeric_limits<mach_msg_type_number_t>::max)());
        if (!nChunkSize) break;

        bool bProtectionChanged = false;
        if (!(nOriginalProtection & VM_PROT_WRITE)) {
            const vm_prot_t nWritableProtection = VM_PROT_READ | VM_PROT_WRITE;
            kern_return_t protectResult = mach_vm_protect(hProcess, nCurrentAddress, (mach_vm_size_t)nChunkSize, FALSE, nWritableProtection);

            if (protectResult != KERN_SUCCESS) {
                protectResult = mach_vm_protect(hProcess, nCurrentAddress, (mach_vm_size_t)nChunkSize, FALSE, nWritableProtection | VM_PROT_COPY);
            }

            if (protectResult != KERN_SUCCESS) break;
            bProtectionChanged = true;
        }

        const kern_return_t writeResult = mach_vm_write(hProcess, nCurrentAddress, (vm_offset_t)(pData + (size_t)nResult), (mach_msg_type_number_t)nChunkSize);

#if defined(Q_PROCESSOR_ARM_64)
        if (writeResult == KERN_SUCCESS) {
            vm_machine_attribute_val_t nCacheOperation = MATTR_VAL_CACHE_FLUSH;
            const kern_return_t cacheResult = vm_machine_attribute(hProcess, nCurrentAddress, (mach_vm_size_t)nChunkSize, MATTR_CACHE, &nCacheOperation);

            if (cacheResult != KERN_SUCCESS) {
                qWarning("Cannot flush the remote instruction cache: %d", cacheResult);
            }
        }
#endif

        if (bProtectionChanged) {
            const kern_return_t restoreResult = mach_vm_protect(hProcess, nCurrentAddress, (mach_vm_size_t)nChunkSize, FALSE, nOriginalProtection);

            if (restoreResult != KERN_SUCCESS) {
                qWarning("Cannot restore remote memory protection: %d", restoreResult);
            }
        }

        if (writeResult != KERN_SUCCESS) break;
#else
        break;
#endif
        nResult += nChunkSize;
        if (!nChunkSize) break;
    }

    return nResult;
}

QByteArray XProcess::read_array(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nSize)
{
    if (!nSize || (nSize > (quint64)(std::numeric_limits<qint32>::max)())) return QByteArray();

    QByteArray baResult((qint32)nSize, Qt::Uninitialized);
    const quint64 nRead = read_array(hProcess, nAddress, baResult.data(), nSize);
    if (nRead > nSize) return QByteArray();
    baResult.resize((qint32)nRead);
    return baResult;
}

QString XProcess::read_ansiString(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize)
{
    if (!nMaxSize || (nMaxSize > (quint64)(std::numeric_limits<qint32>::max)()) || (nAddress > ((std::numeric_limits<quint64>::max)() - (nMaxSize - 1)))) {
        return QString();
    }

    QByteArray data;
    data.reserve((qint32)nMaxSize);
    for (quint64 i = 0; i < nMaxSize; i++) {
        char value = 0;
        if (read_array(hProcess, nAddress + i, &value, 1) != 1 || !value) break;
        data.append(value);
    }

    return QString::fromLatin1(data.constData(), data.size());
}

QString XProcess::read_unicodeString(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize)
{
    if (!nMaxSize || (nMaxSize > (quint64)(std::numeric_limits<qint32>::max)()) || (nMaxSize > ((std::numeric_limits<quint64>::max)() / 2)) ||
        (nAddress > ((std::numeric_limits<quint64>::max)() - (nMaxSize * 2 - 1)))) {
        return QString();
    }

    QVector<quint16> data;
    data.reserve((qint32)nMaxSize);
    for (quint64 i = 0; i < nMaxSize; i++) {
        quint16 value = 0;
        if (read_array(hProcess, nAddress + i * 2, reinterpret_cast<char *>(&value), sizeof(value)) != sizeof(value)) break;
        value = qFromLittleEndian(value);
        if (!value) break;
        data.append(value);
    }

    return QString::fromUtf16(reinterpret_cast<const char16_t *>(data.constData()), data.size());
}

QString XProcess::read_utf8String(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize)
{
    if (!nMaxSize || (nMaxSize > (quint64)(std::numeric_limits<qint32>::max)()) || (nAddress > ((std::numeric_limits<quint64>::max)() - (nMaxSize - 1)))) {
        return QString();
    }

    QByteArray data;
    data.reserve((qint32)nMaxSize);
    for (quint64 i = 0; i < nMaxSize; i++) {
        char value = 0;
        if (read_array(hProcess, nAddress + i, &value, 1) != 1 || !value) break;
        data.append(value);
    }

    return QString::fromUtf8(data.constData(), data.size());
}
#ifdef Q_OS_WIN
qint64 XProcess::getTEBAddress(qint64 nThreadID)
{
    qint64 nResult = 0;

    void *pThread = openThread(nThreadID);

    if (pThread) {
        nResult = getTEBAddress(pThread);

        closeProcess(pThread);
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getTEBAddress(X_HANDLE hThread)
{
    qint64 nResult = -1;

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll) {
        S_THREAD_BASIC_INFORMATION tbi = {};

        pfnNtQueryInformationThread gNtQueryInformationThread = (pfnNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");

        if (gNtQueryInformationThread) {
            LONG nTemp = 0;
            gNtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), (PULONG)&nTemp);  // mb TODO error handle
            nResult = (qint64)tbi.TebBaseAddress;
        }
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getPEBAddress(qint64 nProcessID)
{
    qint64 nResult = 0;

    void *pProcess = openProcess(nProcessID);

    if (pProcess) {
        nResult = getPEBAddress(pProcess);

        closeProcess(pProcess);
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getPEBAddress(X_HANDLE hProcess)
{
    qint64 nResult = -1;

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll) {
        S_PROCESS_BASIC_INFORMATION pbi = {};

        pfnNtQueryInformationProcess gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

        if (gNtQueryInformationProcess) {
            LONG nTemp = 0;
            if (gNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), (PULONG)&nTemp) == ERROR_SUCCESS) {
                nResult = (qint64)pbi.PebBaseAddress;
            }
        }
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
QList<qint64> XProcess::getTEBAddresses(qint64 nProcessID)
{
    QList<qint64> listResult;

    QList<qint64> listThreadIDs = getThreadIDsList(nProcessID);

    qint32 nNumberOfThreads = listThreadIDs.count();

    for (qint32 i = 0; i < nNumberOfThreads; i++) {
        qint64 nThreadID = getTEBAddress(listThreadIDs.at(i));

        listResult.append(nThreadID);
    }

    return listResult;
}
#endif
#ifdef Q_OS_WIN
QList<XProcess::WINSYSHANDLE> XProcess::getOpenHandles(qint64 nProcessID)
{
    QList<XProcess::WINSYSHANDLE> listResult;

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll) {
        pfnNtQuerySystemInformation gNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");

        if (gNtQuerySystemInformation) {
            qint32 nMemorySize = 0x10000;
            void *pMemory = malloc(nMemorySize);

            NTSTATUS status = ERROR_SUCCESS;

            while (true) {
                XBinary::_zeroMemory((char *)pMemory, nMemorySize);

                status = gNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, pMemory, nMemorySize, NULL);

                if (status != 0xC0000004)  // STATUS_INFO_LENGTH_MISMATCH
                {
                    break;
                }

                nMemorySize *= 2;
                pMemory = realloc(pMemory, nMemorySize);
            }

            if (status == ERROR_SUCCESS) {
                S_SYSTEM_HANDLE_INFORMATION *pSHI = (S_SYSTEM_HANDLE_INFORMATION *)pMemory;

                for (qint32 i = 0; i < (qint32)(pSHI->NumberOfHandles); i++) {
                    if ((pSHI->Handles[i].UniqueProcessId == nProcessID) || (nProcessID == -1)) {
                        WINSYSHANDLE record = {};

                        record.nProcessID = pSHI->Handles[i].UniqueProcessId;
                        record.nCreatorBackTraceIndex = pSHI->Handles[i].CreatorBackTraceIndex;
                        record.nHandle = pSHI->Handles[i].HandleValue;
                        record.nAccess = pSHI->Handles[i].GrantedAccess;
                        record.nFlags = pSHI->Handles[i].HandleAttributes;
                        record.nObjectAddress = (quint64)pSHI->Handles[i].Object;
                        record.nObjectTypeNumber = pSHI->Handles[i].ObjectTypeIndex;

                        listResult.append(record);
                    }
                }
            }

            free(pMemory);
        }
    }

    return listResult;
}
#endif
#ifdef Q_OS_WIN
QList<XProcess::WINSYSHANDLE> XProcess::getOpenHandlesEx(qint64 nProcessID)
{
    QList<XProcess::WINSYSHANDLE> listResult;

    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll) {
        pfnNtQuerySystemInformation gNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");

        if (gNtQuerySystemInformation) {
            qint32 nMemorySize = 0x10000;
            void *pMemory = malloc(nMemorySize);

            NTSTATUS status = ERROR_SUCCESS;

            while (true) {
                XBinary::_zeroMemory((char *)pMemory, nMemorySize);

                status = gNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x40, pMemory, nMemorySize, NULL);

                if (status != 0xC0000004)  // STATUS_INFO_LENGTH_MISMATCH
                {
                    break;
                }

                nMemorySize *= 2;
                pMemory = realloc(pMemory, nMemorySize);
            }

            if (status == ERROR_SUCCESS) {
                S_SYSTEM_HANDLE_INFORMATION_EX *pSHI = (S_SYSTEM_HANDLE_INFORMATION_EX *)pMemory;

                for (qint32 i = 0; i < (qint32)(pSHI->NumberOfHandles); i++) {
                    if ((pSHI->Handles[i].UniqueProcessId == nProcessID) || (nProcessID == -1)) {
                        WINSYSHANDLE record = {};

                        record.nProcessID = pSHI->Handles[i].UniqueProcessId;
                        record.nCreatorBackTraceIndex = pSHI->Handles[i].CreatorBackTraceIndex;
                        record.nHandle = pSHI->Handles[i].HandleValue;
                        record.nAccess = pSHI->Handles[i].GrantedAccess;
                        record.nFlags = pSHI->Handles[i].HandleAttributes;
                        record.nObjectAddress = (quint64)pSHI->Handles[i].Object;
                        record.nObjectTypeNumber = pSHI->Handles[i].ObjectTypeIndex;

                        listResult.append(record);
                    }
                }
            }

            free(pMemory);
        }
    }

    return listResult;
}

quint64 XProcess::getSystemEPROCESSAddress()
{
    quint64 nResult = 0;

    QList<XProcess::WINSYSHANDLE> listHandles = getOpenHandlesEx(4);

    qint32 nNumberOfRecords = listHandles.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (listHandles.at(i).nObjectTypeNumber == 7) {
            // Take the first
            nResult = listHandles.at(i).nObjectAddress;

            break;
        }
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::getLastErrorAsString()
{
    QString sResult;

    quint32 nLastError = GetLastError();

    if (nLastError) {
        LPWSTR messageBuffer = nullptr;

        size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, nLastError,
                                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

        sResult = QString::fromWCharArray(messageBuffer, (qint32)size);

        LocalFree(messageBuffer);
    }

    return sResult;
}
#endif
#ifdef Q_OS_WIN
void XProcess::getCallStack(X_HANDLE hProcess, X_HANDLE hThread)
{
    // mb TODO suspend
    //    CONTEXT context;
    //    memset(&context, 0, sizeof(CONTEXT));

    //    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    //    if (GetThreadContext(hThread, &context)) {
    //        STACKFRAME64 frame;
    //        ZeroMemory(&frame, sizeof(STACKFRAME64));

    // #ifdef Q_PROCESSOR_X86_32
    //         DWORD machineType = IMAGE_FILE_MACHINE_I386;
    //         frame.AddrPC.Offset = context.Eip;
    //         frame.AddrPC.Mode = AddrModeFlat;
    //         frame.AddrFrame.Offset = context.Ebp;
    //         frame.AddrFrame.Mode = AddrModeFlat;
    //         frame.AddrStack.Offset = context.Esp;
    //         frame.AddrStack.Mode = AddrModeFlat;
    // #endif
    // #ifdef Q_PROCESSOR_X86_64
    //         DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
    //         frame.AddrPC.Offset = context.Rip;
    //         frame.AddrPC.Mode = AddrModeFlat;
    //         frame.AddrFrame.Offset = context.Rbp;
    //         frame.AddrFrame.Mode = AddrModeFlat;
    //         frame.AddrStack.Offset = context.Rsp;
    //         frame.AddrStack.Mode = AddrModeFlat;
    // #endif
    //         for (qint32 i = 0; i < 100; i++) {
    //             if (!StackWalk64(machineType, hProcess, hThread, &frame, &context, NULL, NULL, NULL, NULL)) {
    //                 break;
    //             }

    //            if (frame.AddrPC.Offset != 0) {
    // #ifdef QT_DEBUG
    //                qDebug("Frame: %s", XBinary::valueToHexEx(frame.AddrFrame.Offset).toLatin1().data());
    //                qDebug("PC: %s", XBinary::valueToHexEx(frame.AddrPC.Offset).toLatin1().data());
    //                qDebug("Return: %s", XBinary::valueToHexEx(frame.AddrReturn.Offset).toLatin1().data());
    //                qDebug("Stack: %s", XBinary::valueToHexEx(frame.AddrStack.Offset).toLatin1().data());
    // #endif
    //                // TODO
    //            } else {
    //                // END
    //                break;
    //            }
    //        }
    //    }
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getProcessIDByHandle(X_HANDLE hProcess)
{
    qint64 nResult = 0;

    nResult = GetProcessId(hProcess);

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getThreadIDByHandle(X_HANDLE hThread)
{
    qint64 nResult = 0;

    nResult = GetThreadId(hThread);

    return nResult;
}
#endif

// XBinary::OSINFO XProcess::getOsInfo()
// {
//     XBinary::OSINFO result = {};
// #ifdef Q_OS_WIN
//     result.osName = XBinary::OSNAME_WINDOWS;
//     // TODO OS Version

//     OSVERSIONINFOEXW ovi = {};

//     ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

//     GetVersionExW((OSVERSIONINFOW *)&ovi);  // TODO Check

//     result.sBuild = QString("%1.%2.%3").arg(QString::number(ovi.dwMajorVersion), QString::number(ovi.dwMinorVersion), QString::number(ovi.dwBuildNumber));

//     SYSTEM_INFO si = {};
//     GetSystemInfo(&si);

//     if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) result.sArch = "I386";
//     else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) result.sArch = "AMD64";
//     else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) result.sArch = "IA64";
//     else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) result.sArch = "ARM";
//         // else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64)       result.sArch="ARM64"; // TODO Macros
// #endif
// #ifdef Q_OS_LINUX
//     result.osName = XBinary::OSNAME_LINUX;
// #ifdef Q_PROCESSOR_X86_32
//     result.sArch = "I386";
// #endif
// #ifdef Q_PROCESSOR_X86_64
//     result.sArch = "AMD64";
// #endif
// #endif
//     if (sizeof(char *) == 8) {
//         result.mode = XBinary::MODE_64;
//     } else {
//         result.mode = XBinary::MODE_32;
//     }

//     return result;
// }

QList<XProcess::MODULE> XProcess::getModulesList(X_ID nProcessID, XBinary::PDSTRUCT *pPdStruct)
{
    XBinary::PDSTRUCT pdStructEmpty = XBinary::createPdStruct();

    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }

    QList<MODULE> listResult;

#ifdef Q_OS_WIN
    HANDLE hModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)nProcessID);

    if (hModules != INVALID_HANDLE_VALUE) {
        tagMODULEENTRY32W me32 = {};
        me32.dwSize = sizeof(tagMODULEENTRY32W);

        if (Module32FirstW(hModules, &me32)) {
            do {
                XProcess::MODULE record = {};

                record.nAddress = (XADDR)me32.modBaseAddr;
                record.nSize = (qint64)me32.modBaseSize;
                record.sName = QString::fromWCharArray(me32.szModule);
                record.sFileName = QString::fromWCharArray(me32.szExePath);

                listResult.append(record);
            } while (Module32NextW(hModules, &me32) && (!(pPdStruct->bIsStop)));
        }

        CloseHandle(hModules);
    }
#endif
#ifdef Q_OS_LINUX
    QList<MEMORY_REGION> listMR = getMemoryRegionsList_Id(nProcessID, 0, 0xFFFFFFFFFFFFFFFF);

    qint32 nNumberOfRecords = listMR.count();

    QMap<QString, quint64> mapImageBase;
    QMap<QString, quint64> mapImageSize;

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (listMR.at(i).nFile) {
            QString sFileName = listMR.at(i).sFileName;

            if (!(mapImageBase.value(sFileName))) {
                mapImageBase.insert(sFileName, listMR.at(i).nAddress);
            }

            mapImageSize.insert(sFileName, mapImageSize.value(sFileName) + listMR.at(i).nSize);
        }
    }

    QList<quint64> listImageBases = mapImageBase.values();

    std::sort(listImageBases.begin(), listImageBases.end());

    nNumberOfRecords = listImageBases.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        quint64 nImageBase = listImageBases.at(i);
        QString sFileName = mapImageBase.key(nImageBase);

        MODULE record = {};

        record.nAddress = nImageBase;
        record.nSize = mapImageSize.value(sFileName);
        record.sName = QFileInfo(sFileName).fileName();
        record.sFileName = sFileName;

        listResult.append(record);
    }
#endif
#ifdef Q_OS_MAC
    task_t task = 0;
    task_for_pid(mach_task_self(), nProcessID, &task);

    task_dyld_info dyld_info = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
        // TODO
    }
#endif

    return listResult;
}

XProcess::MODULE XProcess::getModuleByAddress(QList<MODULE> *pListModules, quint64 nAddress)
{
    MODULE result = {};

    qint32 nNumberOfModules = pListModules->count();

    for (qint32 i = 0; i < nNumberOfModules; i++) {
        if ((pListModules->at(i).nAddress <= nAddress) && (nAddress < (pListModules->at(i).nAddress + pListModules->at(i).nSize))) {
            result = pListModules->at(i);

            break;
        }
    }

    return result;
}

XProcess::MODULE XProcess::getModuleByFileName(QList<MODULE> *pListModules, const QString &sFileName)
{
    MODULE result = {};

    qint32 nNumberOfModules = pListModules->count();

    for (qint32 i = 0; i < nNumberOfModules; i++) {
        if (pListModules->at(i).sFileName == sFileName) {
            result = pListModules->at(i);

            break;
        }
    }

    return result;
}

bool XProcess::isAddressInMemoryRegion(MEMORY_REGION *pMemoryRegion, XADDR nAddress)
{
    bool bResult = false;

    if ((pMemoryRegion->nAddress <= nAddress) && (nAddress < (pMemoryRegion->nAddress + pMemoryRegion->nSize))) {
        bResult = true;
    }

    return bResult;
}

XProcess::MEMORY_REGION XProcess::getMemoryRegionByAddress(QList<MEMORY_REGION> *pListMemoryRegions, XADDR nAddress)
{
    MEMORY_REGION result = {};

    qint32 nNumberOfRecords = pListMemoryRegions->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        MEMORY_REGION memoryRegion = pListMemoryRegions->at(i);

        if (isAddressInMemoryRegion(&memoryRegion, nAddress)) {
            result = pListMemoryRegions->at(i);

            break;
        }
    }

    return result;
}

XProcess::MEMORY_REGION XProcess::getMemoryRegionByAddress(X_ID nProcessID, XADDR nAddress)
{
    MEMORY_REGION result = {};
#ifdef Q_OS_WIN
    MEMORY_BASIC_INFORMATION mbi = {};

    X_HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, (DWORD)nProcessID);

    if (hProcess) {
        if (VirtualQueryEx(hProcess, (LPCVOID)nAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            result.nType = mbi.Type;

            if (result.nType) {
                result.nAddress = (XADDR)mbi.BaseAddress;
                result.nSize = (qint64)mbi.RegionSize;
                result.mf = protectToFlags(mbi.Protect);
                result.nAllocationBase = (XADDR)mbi.AllocationBase;
                result.mfAllocation = protectToFlags(mbi.AllocationProtect);
                result.nState = mbi.State;
            }
        }

        CloseHandle(hProcess);
    }
#endif
#ifdef Q_OS_LINUX
    X_HANDLE_MQ hProcess = openMemoryQuery(nProcessID);

    if (hProcess) {
        QList<XProcess::MEMORY_REGION> listRegions = XProcess::getMemoryRegionsList_Handle(hProcess, nAddress, 0);

        if (listRegions.count()) {
            result = listRegions.at(0);
        }

        closeMemoryQuery(hProcess);
    }
#endif
    return result;
}

QString XProcess::memoryFlagsToString(MEMORY_FLAGS mf)
{
    QString sResult;

#ifdef Q_OS_WIN
    if (mf.bGuard) sResult += "G";
#endif
    if (mf.bRead) sResult += "R";
    if (mf.bWrite) sResult += "W";
    if (mf.bExecute) sResult += "E";
#ifdef Q_OS_WIN
    if (mf.bCopy) sResult += "C";
#endif
#ifdef Q_OS_LINUX
    if (mf.bShare) sResult += "S";
    if (mf.bPrivate) sResult += "P";
#endif
#ifdef Q_OS_MACOS
    if (mf.bShare) sResult += "S";
    if (mf.bReserved) sResult += "res";
#endif

    return sResult;
}

quint32 XProcess::getMemoryRegionsListHash_Handle(X_HANDLE_MQ hProcess)
{
    quint32 nResult = 0;
#ifdef Q_OS_WIN
    XADDR nCurrentAddress = 0;

    while (true) {
        nCurrentAddress = S_ALIGN_DOWN(nCurrentAddress, 0x1000);

        MEMORY_BASIC_INFORMATION mbi = {};

        if (VirtualQueryEx(hProcess, (LPCVOID)nCurrentAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            nResult = XBinary::_getCRC32((char *)&mbi, sizeof(mbi), nResult, XBinary::_getCRC32Table_EDB88320());

            nCurrentAddress += (XADDR)mbi.RegionSize;
        } else {
            break;
        }
    }
#else
    Q_UNUSED(hProcess)
#endif

    return nResult;
}

quint32 XProcess::getMemoryRegionsListHash_Id(X_ID nProcessID)
{
    quint32 nResult = 0;
#ifdef Q_OS_WIN
    Q_UNUSED(nProcessID)
#endif
#ifdef Q_OS_LINUX
    nResult = XBinary::_getCRC32ByFileContent(QString("/proc/%1/maps").arg(nProcessID));
#endif
    return nResult;
}

quint32 XProcess::getModulesListHash(X_ID nProcessID)
{
    quint32 nResult = 0;
#ifdef Q_OS_WIN
    HANDLE hModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)nProcessID);

    if (hModules != INVALID_HANDLE_VALUE) {
        tagMODULEENTRY32W me32 = {};
        me32.dwSize = sizeof(tagMODULEENTRY32W);

        if (Module32FirstW(hModules, &me32)) {
            do {
                nResult = XBinary::_getCRC32((char *)&me32, sizeof(me32), nResult, XBinary::_getCRC32Table_EDB88320());
            } while (Module32NextW(hModules, &me32));
        }

        CloseHandle(hModules);
    }
#endif
#ifdef Q_OS_LINUX
    nResult = XBinary::_getCRC32ByFileContent(QString("/proc/%1/maps").arg(nProcessID));
#endif
    return nResult;
}

quint32 XProcess::getThreadsListHash(X_ID nProcessID)
{
    qint32 nResult = 0;
#ifdef Q_OS_WIN
    HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, (DWORD)nProcessID);

    if (hThreads != INVALID_HANDLE_VALUE) {
        THREADENTRY32 thread = {};
        thread.dwSize = sizeof(tagTHREADENTRY32);

        if (Thread32First(hThreads, &thread)) {
            do {
                nResult = XBinary::_getCRC32((char *)&thread, sizeof(thread), nResult, XBinary::_getCRC32Table_EDB88320());
            } while (Thread32Next(hThreads, &thread));
        }

        CloseHandle(hThreads);
    }
#endif
#ifdef Q_OS_LINUX
    nResult = XBinary::_getCRC32ByDirectory(QString("/proc/%1/task").arg(nProcessID), false);
#endif
    return nResult;
}

quint32 XProcess::getProcessesListHash()
{
    // TODO
    return 0;
}

QString XProcess::memoryRegionToString(MEMORY_REGION memoryRegion)
{
    QString sResult;

    sResult = QString("%1 - %2").arg(XBinary::valueToHexEx(memoryRegion.nAddress), XBinary::valueToHexEx(memoryRegion.nAddress + memoryRegion.nSize));

    return sResult;
}

XBinary::_MEMORY_MAP XProcess::getMemoryMapByHandle(X_HANDLE_MQ hProcess)
{
    XBinary::_MEMORY_MAP result = {};
    _setMemoryMapHeader(&result);

    QList<MEMORY_REGION> listMemoryRegions = getMemoryRegionsList_Handle(hProcess, 0, 0xFFFFFFFFFFFFFFFF);
    result.listRecords = convertMemoryRegionsToMemoryRecords(&listMemoryRegions);

    return result;
}

XBinary::_MEMORY_MAP XProcess::getMemoryMapById(X_ID nProcessID)
{
    XBinary::_MEMORY_MAP result = {};
    _setMemoryMapHeader(&result);

    QList<MEMORY_REGION> listMemoryRegions = getMemoryRegionsList_Id(nProcessID, 0, 0xFFFFFFFFFFFFFFFF);
    result.listRecords = convertMemoryRegionsToMemoryRecords(&listMemoryRegions);

    return result;
}

QList<XBinary::_MEMORY_RECORD> XProcess::convertMemoryRegionsToMemoryRecords(QList<MEMORY_REGION> *pListMemoryRegions)
{
    QList<XBinary::_MEMORY_RECORD> listResult;

    qint32 nNumberOfRecords = pListMemoryRegions->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XBinary::_MEMORY_RECORD record = {};
        record.bIsVirtual = true;
        record.nOffset = -1;
        record.nAddress = pListMemoryRegions->at(i).nAddress;
        record.nSize = pListMemoryRegions->at(i).nSize;
        record.nIndex = i;
        record.filePart = XBinary::FILEPART_REGION;

        listResult.append(record);
    }

    return listResult;
}

bool XProcess::isModulePesent(QString sModuleName, QList<MODULE> *pListModules, XBinary::PDSTRUCT *pPdStruct)
{
    bool bResult = false;

    qint32 nNumberOfRecords = pListModules->count();

    for (qint32 i = 0; (i < nNumberOfRecords) && (!(pPdStruct->bIsStop)); i++) {
        if (pListModules->at(i).sName.toLower() == sModuleName.toLower()) {
            bResult = true;
            break;
        }
    }

    return bResult;
}

void XProcess::_setMemoryMapHeader(XBinary::_MEMORY_MAP *pMemoryMap)
{
    pMemoryMap->fileType = XBinary::FT_PROCESS;
    pMemoryMap->endian = XBinary::ENDIAN_LITTLE;  // TODO
    if (sizeof(void *) == 8) {
        pMemoryMap->mode = XBinary::MODE_64;
    } else {
        pMemoryMap->mode = XBinary::MODE_32;
    }
    pMemoryMap->nModuleAddress = 0;
    pMemoryMap->sArch = "X86";  // TODO !!!
}
