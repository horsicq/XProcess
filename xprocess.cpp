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
#include "xprocess.h"

#ifdef Q_OS_LINUX
qint64 _openLargeFile(QString sFileName, qint32 nFlags)
{
    qint64 nResult = open64(sFileName.toUtf8().data(), nFlags);

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
quint32 _readLargeFile(qint32 nFD, quint64 nOffset, char *pData, quint32 nDataSize)
{
    quint32 nResult = 0;

    if (lseek64(nFD, nOffset, SEEK_SET) != -1) {
        nResult = pread64(nFD, pData, nDataSize, nOffset);
    }

    return nResult;
}
#endif

#ifdef Q_OS_LINUX
quint32 _writeLargeFile(qint32 nFD, quint64 nOffset, const char *pData, quint32 nDataSize)
{
    quint32 nResult = 0;

    if (lseek64(nFD, nOffset, SEEK_SET) != -1) {
        nResult = pwrite64(nFD, pData, nDataSize, nOffset);
    }

    return nResult;
}
#endif

XProcess::XProcess(QObject *pParent) : XIODevice(pParent)
{
    g_nProcessID = 0;
    g_hProcess = 0;
}

XProcess::XProcess(X_ID nProcessID, XADDR nAddress, quint64 nSize, QObject *pParent) : XProcess(pParent)
{
    g_nProcessID = nProcessID;

    setInitLocation(nAddress);
    setSize(nSize);
}

XProcess::XProcess(XADDR nAddress, quint64 nSize, X_HANDLE hHandle, QObject *pParent) : XProcess(pParent)
{
    g_hProcess = hHandle;

    setInitLocation(nAddress);
    setSize(nSize);
}

bool XProcess::open(OpenMode mode)
{
    bool bResult = false;

    if (g_nProcessID && size())  // TODO more checks
    {
#ifdef Q_OS_WIN
        quint32 nFlag = 0;

        if (mode == ReadOnly) {
            nFlag = PROCESS_VM_READ;
        } else if (mode == WriteOnly) {
            nFlag = PROCESS_VM_WRITE;
        } else if (mode == ReadWrite) {
            nFlag = PROCESS_ALL_ACCESS;
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
            g_hProcess = (void *)nFD;

            bResult = true;
        }
#endif
#ifdef Q_OS_MACOS
        mach_port_name_t task = 0;
        kern_return_t error = task_for_pid(mach_task_self(), g_nProcessID, &task);

        if (error != KERN_SUCCESS) {
            g_hProcess = task;
            bResult = true;
        }
#endif
    } else if (g_hProcess && size())  // TODO more checks
    {
        bResult = true;
    }

    if (bResult) {
        setOpenMode(mode);
    }

    return bResult;
}

void XProcess::close()
{
    bool bSuccess = false;

    if (g_nProcessID && g_hProcess) {
#ifdef Q_OS_WIN
        bSuccess = CloseHandle(g_hProcess);
#endif
#ifdef Q_OS_LINUX
        bSuccess = _closeLargeFile((qint64)g_hProcess);
#endif
    } else if (g_hProcess) {
        bSuccess = true;
    }

    if (bSuccess) {
        setOpenMode(NotOpen);
    }
}

qint64 XProcess::readData(char *pData, qint64 nMaxSize)
{
    qint64 nResult = 0;

    char *_pData = pData;
    qint64 _nPos = pos();
    quint64 nStartOffset = getInitLocation() + _nPos;

    nMaxSize = qMin(nMaxSize, (qint64)(size() - _nPos));

    for (qint64 i = 0; i < nMaxSize;) {
        //    #ifdef QT_DEBUG
        //        QString sDebugString=QString("%1").arg(_nPos+g_nAddress,0,16);
        //        qDebug("Address: %s",sDebugString.toLatin1().data());
        //    #endif

        qint64 nDelta = S_ALIGN_UP(_nPos, N_BUFFER_SIZE) - _nPos;

        if (nDelta == 0) {
            nDelta = N_BUFFER_SIZE;
        }

        nDelta = qMin(nDelta, (qint64)(nMaxSize - i));

        if (nDelta == 0) {
            break;
        }

#ifdef Q_OS_WIN
        SIZE_T nSize = 0;

        if (!ReadProcessMemory(g_hProcess, (LPVOID *)(getInitLocation() + _nPos), _pData, (SIZE_T)nDelta, &nSize)) {
            break;
        }

        if (nSize != (SIZE_T)nDelta) {
            break;
        }
#endif
#ifdef Q_OS_LINUX
        if (nDelta != _readLargeFile((qint64)g_hProcess, getInitLocation() + _nPos, _pData, nDelta)) {
            break;
        }
#endif
        _nPos += nDelta;
        _pData += nDelta;
        nResult += nDelta;
        i += nDelta;
    }

    emit readDataSignal(nStartOffset, pData, nMaxSize);

#ifdef Q_OS_WIN
    // TODO error string
#endif

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
    qint64 nResult = 0;

    qint64 _nPos = pos();
    quint64 nStartOffset = getInitLocation() + _nPos;

    nMaxSize = qMin(nMaxSize, (qint64)(size() - _nPos));

    char *_pDataOrig = new char[nMaxSize];

    XBinary::_copyMemory(_pDataOrig, (char *)pData, nMaxSize);

    emit writeDataSignal(nStartOffset, _pDataOrig, nMaxSize);

    char *_pData = _pDataOrig;

    for (qint64 i = 0; i < nMaxSize;) {
        qint64 nDelta = S_ALIGN_UP(_nPos, N_BUFFER_SIZE) - _nPos;

        if (nDelta == 0) {
            nDelta = N_BUFFER_SIZE;
        }

        nDelta = qMin(nDelta, (qint64)(nMaxSize - i));
#ifdef Q_OS_WIN
        SIZE_T nSize = 0;

        if (!WriteProcessMemory(g_hProcess, (LPVOID *)(_nPos + getInitLocation()), _pData, (SIZE_T)nDelta, &nSize)) {
            break;
        }

        if (nSize != (SIZE_T)nDelta) {
            break;
        }
#endif
#ifdef Q_OS_LINUX
        if (nDelta != _writeLargeFile((qint64)g_hProcess, getInitLocation() + _nPos, _pData, nDelta)) {
            break;
        }
#endif
        _nPos += nDelta;
        _pData += nDelta;
        nResult += nDelta;
        i += nDelta;
    }

    delete[] _pDataOrig;

#ifdef Q_OS_WIN
    // TODO error string
#endif

#ifdef QT_DEBUG
    QString sErrorString = errorString();
    if ((sErrorString != "") && (sErrorString != "Unknown error")) {
        qDebug("%s", sErrorString.toLatin1().data());
    }
#endif

    return nResult;
}

QList<XProcess::PROCESS_INFO> XProcess::getProcessesList(bool bShowAll)
{
    QList<PROCESS_INFO> listResult;
#ifdef Q_OS_WIN
    HANDLE hProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcesses != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32 = {};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hProcesses, &pe32)) {
            do {
                PROCESS_INFO processInfo = getInfoByProcessID(pe32.th32ProcessID);

                bool bSuccess = false;

                if (processInfo.nID) {
                    bSuccess = true;
                } else if (bShowAll) {
                    processInfo.nID = pe32.th32ProcessID;
                    processInfo.sName = QString::fromWCharArray(pe32.szExeFile);

                    bSuccess = true;
                }

                if (bSuccess) {
                    listResult.append(processInfo);
                }
            } while (Process32NextW(hProcesses, &pe32));
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

        int nNumberOfProcesses = nProcBuffSize / sizeof(kinfo_proc);

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
                memoryRegion.nAddress = (qint64)mbi.BaseAddress;
                memoryRegion.nSize = (qint64)mbi.RegionSize;
                memoryRegion.mf = protectToFlags(mbi.Protect);
                memoryRegion.nAllocationBase = (qint64)mbi.AllocationBase;
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
        result.nAddress = (qint64)mbi.BaseAddress;
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
            MODULEENTRY32 me32 = {};
            me32.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(hModule, &me32)) {
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
        nResult = (qint64)mbi.BaseAddress;
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
        qDebug("Unknown");
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
                sResult = QString::fromUtf16((ushort *)wszBuffer);
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
            QString sDisk = QString::fromUtf16((ushort *)(pwszBuffer + i));
            sDisk = sDisk.remove("\\");

            i += sDisk.size() + 1;

            if (QueryDosDeviceW((WCHAR *)sDisk.utf16(), wszNtBuffer, sizeof(wszNtBuffer))) {
                QString sNt = QString::fromUtf16((const ushort *)wszNtBuffer);

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
    QFile *pFile = static_cast<QFile *>(hProcess);

    if (pFile) {
        pFile->close();
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
    quint64 nResult = 0;
#ifdef Q_OS_WIN
    SIZE_T _nSize = 0;

    if (ReadProcessMemory(hProcess, (LPVOID *)nAddress, pData, (SIZE_T)nSize, &_nSize)) {
        nResult = (quint64)_nSize;
    }
#endif
#ifdef Q_OS_LINUX
    qint32 nFD = (qint32)((qint64)hProcess & 0xFFFFFFFF);

    nResult = _readLargeFile(nFD, nAddress, pData, nSize);
#endif
#ifdef Q_OS_MAC
    task_t task = (task_t)((qint64)hProcess & 0xFFFFFFFF);

    mach_msg_type_number_t _nSize = 0;

    if (mach_vm_read(task, (mach_vm_address_t)nAddress, (mach_vm_size_t)nSize, (vm_offset_t *)pData, &_nSize)) {
        nResult = (quint64)_nSize;
    }
#endif
    return nResult;
}

quint64 XProcess::write_array(X_HANDLE_IO hProcess, quint64 nAddress, char *pData, quint64 nSize)
{
    quint64 nResult = 0;
#ifdef Q_OS_WIN
    SIZE_T _nSize = 0;

    if (WriteProcessMemory(hProcess, (LPVOID *)nAddress, pData, (SIZE_T)nSize, &_nSize)) {
        nResult = (quint64)_nSize;
    }
#endif
#ifdef Q_OS_LINUX
    qint32 nFD = (qint32)((qint64)hProcess & 0xFFFFFFFF);

    nResult = _writeLargeFile(nFD, nAddress, pData, nSize);
#endif
#ifdef Q_OS_MAC
    task_t task = (task_t)((qint64)hProcess & 0xFFFFFFFF);

    mach_msg_type_number_t _nSize = nSize;

    if (vm_write(task, (vm_address_t)nAddress, (vm_offset_t)pData, _nSize)) {
        nResult = (quint64)_nSize;
    }
#endif
    return nResult;
}

QByteArray XProcess::read_array(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nSize)
{
    QByteArray baResult;

    baResult.resize(nSize);
    // TODO Check if fails
    read_array(hProcess, nAddress, baResult.data(), nSize);

    return baResult;
}

QString XProcess::read_ansiString(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize)
{
    char *pBuffer = new char[nMaxSize + 1];
    QString sResult;
    quint32 i = 0;

    for (; i < nMaxSize; i++) {
        if (!read_array(hProcess, nAddress + i, &(pBuffer[i]), 1)) {
            break;
        }

        if (pBuffer[i] == 0) {
            break;
        }
    }

    pBuffer[i] = 0;
    sResult.append(pBuffer);

    delete[] pBuffer;

    return sResult;
}

QString XProcess::read_unicodeString(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize)
{
    QString sResult;

    if (nMaxSize) {
        quint16 *pBuffer = new quint16[nMaxSize + 1];

        for (qint32 i = 0; i < (qint32)nMaxSize; i++) {
            pBuffer[i] = read_uint16(hProcess, nAddress + 2 * i);

            if (pBuffer[i] == 0) {
                break;
            }

            if (i == (qint32)(nMaxSize - 1)) {
                pBuffer[nMaxSize] = 0;
            }
        }

        sResult = QString::fromUtf16(pBuffer);

        delete[] pBuffer;
    }

    return sResult;
}

QString XProcess::read_utf8String(X_HANDLE_IO hProcess, quint64 nAddress, quint64 nMaxSize)
{
    QString sResult;

    if (nMaxSize) {
        qint32 nRealSize = 0;

        for (qint32 i = 0; i < (qint32)nMaxSize; i++) {
            quint8 nByte = read_uint8(hProcess, nAddress + nRealSize);

            if (nByte == 0) {
                break;
            }

            // TODO Check !!!
            if ((nByte >> 7) & 0x1) {
                nRealSize++;
            } else if ((nByte >> 5) & 0x1) {
                nRealSize += 2;
            } else if ((nByte >> 4) & 0x1) {
                nRealSize += 3;
            } else if ((nByte >> 3) & 0x1) {
                nRealSize += 4;
            }
        }

        if (nRealSize) {
            QByteArray baString = read_array(hProcess, nAddress, nRealSize);
            sResult = QString::fromUtf8(baString.data());
        }
    }

    return sResult;
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
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));

    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    if (GetThreadContext(hThread, &context)) {
        STACKFRAME64 frame;
        ZeroMemory(&frame, sizeof(STACKFRAME64));

#ifdef Q_PROCESSOR_X86_32
        DWORD machineType = IMAGE_FILE_MACHINE_I386;
        frame.AddrPC.Offset = context.Eip;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = context.Ebp;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Offset = context.Esp;
        frame.AddrStack.Mode = AddrModeFlat;
#endif
#ifdef Q_PROCESSOR_X86_64
        DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
        frame.AddrPC.Offset = context.Rip;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = context.Rbp;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Offset = context.Rsp;
        frame.AddrStack.Mode = AddrModeFlat;
#endif
        for (qint32 i = 0; i < 100; i++) {
            if (!StackWalk64(machineType, hProcess, hThread, &frame, &context, NULL, NULL, NULL, NULL)) {
                break;
            }

            if (frame.AddrPC.Offset != 0) {
#ifdef QT_DEBUG
                qDebug("Frame: %s", XBinary::valueToHexEx(frame.AddrFrame.Offset).toLatin1().data());
                qDebug("PC: %s", XBinary::valueToHexEx(frame.AddrPC.Offset).toLatin1().data());
                qDebug("Return: %s", XBinary::valueToHexEx(frame.AddrReturn.Offset).toLatin1().data());
                qDebug("Stack: %s", XBinary::valueToHexEx(frame.AddrStack.Offset).toLatin1().data());
#endif
                // TODO
            } else {
                // END
                break;
            }
        }
    }
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

XBinary::OSINFO XProcess::getOsInfo()
{
    XBinary::OSINFO result = {};
#ifdef Q_OS_WIN
    result.osName = XBinary::OSNAME_WINDOWS;
    // TODO OS Version

    OSVERSIONINFOEXA ovi = {};

    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);

    GetVersionExA((OSVERSIONINFOA *)&ovi);

    result.sBuild = QString("%1.%2.%3").arg(QString::number(ovi.dwMajorVersion), QString::number(ovi.dwMinorVersion), QString::number(ovi.dwBuildNumber));

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);

    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) result.sArch = "I386";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) result.sArch = "AMD64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) result.sArch = "IA64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) result.sArch = "ARM";
        // else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64)       result.sArch="ARM64"; // TODO Macros
#endif
#ifdef Q_OS_LINUX
    result.osName = XBinary::OSNAME_LINUX;
#ifdef Q_PROCESSOR_X86_32
    result.sArch = "I386";
#endif
#ifdef Q_PROCESSOR_X86_64
    result.sArch = "AMD64";
#endif
#endif
    if (sizeof(char *) == 8) {
        result.mode = XBinary::MODE_64;
    } else {
        result.mode = XBinary::MODE_32;
    }

    return result;
}

QList<XProcess::MODULE> XProcess::getModulesList(qint64 nProcessID)
{
    QList<MODULE> listResult;

#ifdef Q_OS_WIN
    HANDLE hModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)nProcessID);

    if (hModules != INVALID_HANDLE_VALUE) {
        tagMODULEENTRY32W me32 = {};
        me32.dwSize = sizeof(tagMODULEENTRY32W);

        if (Module32FirstW(hModules, &me32)) {
            do {
                XProcess::MODULE record = {};

                record.nAddress = (quint64)me32.modBaseAddr;
                record.nSize = (quint64)me32.modBaseSize;
                record.sName = QString::fromWCharArray(me32.szModule);
                record.sFileName = QString::fromWCharArray(me32.szExePath);

                listResult.append(record);
            } while (Module32NextW(hModules, &me32));
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
        int z = 0;
        z++;
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

XProcess::MEMORY_REGION XProcess::getMemoryRegionByAddress(QList<MEMORY_REGION> *pListMemoryRegions, quint64 nAddress)
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
        record.type = XBinary::MMT_LOADSEGMENT;

        listResult.append(record);
    }

    return listResult;
}

void XProcess::_setMemoryMapHeader(XBinary::_MEMORY_MAP *pMemoryMap)
{
    pMemoryMap->fileType = XBinary::FT_PROCESS;
    pMemoryMap->bIsBigEndian = false;  // TODO
    if (sizeof(void *) == 8) {
        pMemoryMap->mode = XBinary::MODE_64;
    } else {
        pMemoryMap->mode = XBinary::MODE_32;
    }
    pMemoryMap->nModuleAddress = 0;
    pMemoryMap->sArch = "X86";  // TODO !!!
}
