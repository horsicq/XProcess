/* Copyright (c) 2019-2021 hors<horsicq@gmail.com>
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

XProcess::XProcess(QObject *parent) : QObject(parent)
{

}

QList<XProcess::PROCESS_INFO> XProcess::getProcessesList()
{
    QList<PROCESS_INFO> listResult;
#ifdef Q_OS_WIN
    HANDLE hProcesses=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

    if(hProcesses!=INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe32;
        pe32.dwSize=sizeof(PROCESSENTRY32W);

        if(Process32FirstW(hProcesses,&pe32))
        {
            do
            {
                PROCESS_INFO processInfo=getInfoByProcessID(pe32.th32ProcessID);

                if(processInfo.nID)
                {
                    listResult.append(processInfo);
                }
            }
            while(Process32NextW(hProcesses,&pe32));
        }

        CloseHandle(hProcesses);
    }

#endif
    // TODO Check Mac
#ifdef Q_OS_LINUX
    QDirIterator it("/proc");

    while(it.hasNext())
    {
        QString sRecord=it.next();

        QFileInfo fi(sRecord);

        if(fi.isDir())
        {
            qint64 nPID=fi.baseName().toInt();

            PROCESS_INFO processInfo=getInfoByProcessID(nPID);

            if(processInfo.nID)
            {
                listResult.append(processInfo);
            }
        }
    }
#endif

    return listResult;
}

bool XProcess::setDebugPrivilege(bool bEnable)
{
    return setPrivilege("SeDebugPrivilege",bEnable);
}

bool XProcess::setPrivilege(QString sName, bool bEnable)
{
    bool bResult=true;
#ifdef Q_OS_WIN
    bResult=false;
    HANDLE hToken;

    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
    {
        LUID SeValue;

        if(LookupPrivilegeValueA(nullptr,sName.toLatin1().data(),&SeValue))
        {
            TOKEN_PRIVILEGES tp;

            tp.PrivilegeCount=1;
            tp.Privileges[0].Luid=SeValue;
            tp.Privileges[0].Attributes=bEnable?SE_PRIVILEGE_ENABLED:0;

            AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),nullptr,nullptr);

            bResult=true;
        }

        CloseHandle(hToken);
    }
#endif
    return bResult;
}

QList<XBinary::MEMORY_REGION> XProcess::getMemoryRegionsList(void *hProcess, qint64 nAddress, qint64 nSize)
{
    QList<XBinary::MEMORY_REGION> listResult;
#ifdef Q_OS_WIN
    for(qint64 nCurrentAddress=nAddress;nCurrentAddress<nAddress+nSize;)
    {
        nCurrentAddress=S_ALIGN_DOWN(nCurrentAddress,0x1000);

        MEMORY_BASIC_INFORMATION mbi={};

        if(VirtualQueryEx(hProcess,(LPCVOID)nCurrentAddress,&mbi,sizeof(mbi))==sizeof(mbi))
        {
            XBinary::MEMORY_REGION memoryRegion={};

            memoryRegion.nAddress=(qint64)mbi.BaseAddress;
            memoryRegion.nSize=(qint64)mbi.RegionSize;
            memoryRegion.mf=dwordToFlags(mbi.Protect);

            nCurrentAddress+=memoryRegion.nSize;

            listResult.append(memoryRegion);
        }
        else
        {
            break;
        }
    }
#endif
    return listResult;
}

QList<XBinary::MEMORY_REGION> XProcess::getMemoryRegionsList(qint64 nProcessID, qint64 nAddress, qint64 nSize)
{
    QList<XBinary::MEMORY_REGION> listResult;

    void *pProcess=openProcess(nProcessID);

    if(pProcess)
    {
        listResult=getMemoryRegionsList(pProcess,nAddress,nSize);

        closeProcess(pProcess);
    }

    return listResult;
}

XBinary::MEMORY_REGION XProcess::getMemoryRegion(void *hProcess, qint64 nAddress)
{
    XBinary::MEMORY_REGION result={};
#ifdef Q_OS_WIN
//#ifndef Q_OS_WIN64
//    MEMORY_BASIC_INFORMATION32 mbi={};
//#else
//    MEMORY_BASIC_INFORMATION64 mbi={};
//#endif
    MEMORY_BASIC_INFORMATION mbi={};

    nAddress=S_ALIGN_DOWN(nAddress,0x1000);

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,(MEMORY_BASIC_INFORMATION *)&mbi,sizeof(mbi))==sizeof(mbi))
    {
        result.nAddress=(qint64)mbi.BaseAddress;
        result.nSize=(qint64)mbi.RegionSize;
        result.mf=dwordToFlags(mbi.Protect);
    }

//    // TODO Check
//    if(result.nSize>0x10000)
//    {
//        result.nSize=0x10000;
//    }
#endif
    return result;
}

XBinary::MEMORY_REGION XProcess::getMemoryRegion(qint64 nProcessID, qint64 nAddress)
{
    XBinary::MEMORY_REGION result={};

    void *pProcess=openProcess(nProcessID);

    if(pProcess)
    {
        result=getMemoryRegion(pProcess,nAddress);

        closeProcess(pProcess);
    }

    return result;
}

XBinary::MEMORY_REGION XProcess::getMemoryRegion(HANDLEID handleID, qint64 nAddress)
{
    XBinary::MEMORY_REGION mrResult={};

    if(handleID.hHandle)
    {
        mrResult=getMemoryRegion(handleID.hHandle,nAddress);
    }
    else if(handleID.nID)
    {
        handleID.hHandle=XProcess::openProcess(handleID.nID);

        if(handleID.hHandle)
        {
            mrResult=getMemoryRegion(handleID,nAddress);

            XProcess::closeProcess(handleID.hHandle);
        }
    }

    return mrResult;
}

XProcess::PROCESS_INFO XProcess::getInfoByProcessID(qint64 nProcessID)
{
    PROCESS_INFO result={0};
#ifdef Q_OS_WIN
    if(nProcessID)
    {
        HANDLE hModule=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,(DWORD)nProcessID);

        if(hModule!=INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 me32={};
            me32.dwSize=sizeof(MODULEENTRY32);

            if(Module32First(hModule,&me32))
            {
                if((qint64)me32.modBaseAddr)
                {
                    result.nID=nProcessID;
                    result.nImageAddress=(qint64)me32.modBaseAddr;
                    result.nImageSize=(qint64)me32.modBaseSize;
                    result.sFilePath=QString::fromWCharArray(me32.szExePath);
                    result.sName=QString::fromWCharArray(me32.szModule);
                }
            }

            CloseHandle(hModule);
        }
    }
#endif
#ifdef Q_OS_LINUX
    if(nProcessID)
    {
        // TODO argument
        QFile file;
        file.setFileName(QString("/proc/%1/cmdline").arg(nProcessID));

        if(file.open(QIODevice::ReadOnly))
        {
            QByteArray baData=file.readAll();
            QList<QByteArray> list=baData.split(0);

            if(list.count())
            {
                QString sFilePath=list.at(0).data();

                if(sFilePath!="")
                {
                    QFileInfo fi(sFilePath);

                    if(fi.exists())
                    {
                        result.nID=nProcessID;
                        result.sName=fi.baseName();
                        result.sFilePath=sFilePath;
                    }
                }
            }

            file.close();
        }
    }
#endif
    return result;
}
QList<qint64> XProcess::getThreadIDsList(qint64 nProcessID)
{
    QList<qint64> listResult;

#ifdef Q_OS_WIN
    HANDLE hThreads=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);

    if(hThreads!=INVALID_HANDLE_VALUE)
    {
        tagTHREADENTRY32 thread={};
        thread.dwSize=sizeof(tagTHREADENTRY32);

        if(Thread32First(hThreads,&thread))
        {
            do
            {
                if(thread.th32OwnerProcessID==nProcessID)
                {
                    listResult.append(thread.th32ThreadID);
                }
            }
            while(Thread32Next(hThreads,&thread));
        }

        CloseHandle(hThreads);
    }

#endif

    return listResult;
}

#ifdef Q_OS_WIN
qint64 XProcess::getRegionAllocationSize(void *hProcess,qint64 nRegionBase)
{
    qint64 nResult=0;

    qint64 _nAddress=nRegionBase;

    while(true)
    {
        MEMORY_BASIC_INFORMATION mbi={};

        if(!VirtualQueryEx(hProcess,(LPCVOID)_nAddress,&mbi,sizeof(mbi)))
        {
            break;
        }

        if((mbi.RegionSize)&&((qint64)mbi.AllocationBase==nRegionBase))
        {
            nResult+=mbi.RegionSize;
            _nAddress+=mbi.RegionSize;
        }
        else
        {
            break;
        }
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionAllocationBase(void *hProcess, qint64 nAddress)
{
    qint64 nResult=-1;

    nAddress=S_ALIGN_DOWN(nAddress,0x1000);

    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        nResult=(qint64)mbi.AllocationBase;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionBase(void *hProcess, qint64 nAddress)
{
    qint64 nResult=-1;

    nAddress=S_ALIGN_DOWN(nAddress,0x1000);

    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        nResult=(qint64)mbi.BaseAddress;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionSize(void *hProcess, qint64 nAddress)
{
    qint64 nResult=-1;

    nAddress=S_ALIGN_DOWN(nAddress,0x1000);

    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        nResult=(qint64)mbi.RegionSize;
    }

    return nResult;
}

XBinary::MEMORY_FLAGS XProcess::dwordToFlags(quint32 nValue)
{
    XBinary::MEMORY_FLAGS result={};

    if(nValue==PAGE_READONLY)
    {
        result.bRead=true;
    }
    else if(nValue==PAGE_READWRITE)
    {
        result.bRead=true;
        result.bWrite=true;
    }
    else if(nValue==PAGE_EXECUTE)
    {
        result.bExecute=true;
    }
    else if(nValue==PAGE_EXECUTE_READ)
    {
        result.bRead=true;
        result.bExecute=true;
    }
    else if(nValue==PAGE_EXECUTE_READWRITE)
    {
        result.bRead=true;
        result.bWrite=true;
        result.bWrite=true;
    }
    // TODO more for Windows !

    return result;
}
#endif
#ifdef Q_OS_WIN
XBinary::MEMORY_FLAGS XProcess::getMemoryFlags(void *hProcess, qint64 nAddress)
{
    XBinary::MEMORY_FLAGS result={};
    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        result=dwordToFlags(mbi.Protect);
    }

    return result;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::getFileNameByHandle(void *hHandle)
{
    QString sResult;

    HANDLE hFileMapping=CreateFileMappingW(hHandle,nullptr,PAGE_READONLY,0,GetFileSize(hHandle,nullptr),nullptr);

    if(hFileMapping)
    {
        void *pMem=MapViewOfFile(hFileMapping,FILE_MAP_READ,0,0,0);

        if(pMem)
        {
            WCHAR wszBuffer[1024];

            if(GetMappedFileNameW(GetCurrentProcess(),pMem,wszBuffer,sizeof(wszBuffer)))
            {
                sResult=QString::fromUtf16((ushort *)wszBuffer);
                sResult=convertNtToDosPath(sResult);
            }

            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMapping);
    }

    return sResult;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::convertNtToDosPath(QString sNtPath)
{
    QString sResult=sNtPath;

    qint32 nSize=GetLogicalDriveStringsW(0,0);

    if(nSize)
    {
        WCHAR wszNtBuffer[256];

        WCHAR *pwszBuffer=new WCHAR[nSize+1];

        nSize=GetLogicalDriveStringsW(nSize,pwszBuffer);

        for(qint32 i=0;i<nSize;)
        {
            QString sDisk=QString::fromUtf16((ushort *)(pwszBuffer+i));
            sDisk=sDisk.remove("\\");

            i+=sDisk.size()+1;

            if(QueryDosDeviceW((WCHAR *)sDisk.utf16(),wszNtBuffer,sizeof(wszNtBuffer)))
            {
                QString sNt=QString::fromUtf16((const ushort *)wszNtBuffer);

                QString _sNtPath=sNtPath;
                _sNtPath.resize(sNt.size());

                if(_sNtPath==sNt)
                {
                    sResult=sDisk+sNtPath.mid(sNt.size(),-1);

                    break;
                }
            }
        }

        delete [] pwszBuffer;
    }

    return sResult;
}
#endif

void *XProcess::openProcess(qint64 nProcessID)
{
    void *pResult=0;
#ifdef Q_OS_WIN
    pResult=(void *)OpenProcess(PROCESS_ALL_ACCESS,0,nProcessID);
#endif
    return pResult;
}

void XProcess::closeProcess(void *hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hProcess);
#endif
}

void *XProcess::openThread(qint64 nThreadID)
{
    void *pResult=0;
#ifdef Q_OS_WIN
    pResult=(void *)OpenThread(THREAD_ALL_ACCESS,0,nThreadID);
#endif
    return pResult;
}

void XProcess::closeThread(void *hThread)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hThread);
#endif
}

bool XProcess::isProcessReadable(qint64 nProcessID)
{
    bool bResult=false;

    void *pProcessHandle=openProcess(nProcessID);

    if(pProcessHandle)
    {
        bResult=true;

        closeProcess(pProcessHandle);
    }

    return bResult;
}

quint8 XProcess::read_uint8(void *hProcess, qint64 nAddress)
{
    quint8 nResult=0;

    read_array(hProcess,nAddress,(char *)&nResult,1);

    return nResult;
}

quint16 XProcess::read_uint16(void *hProcess, qint64 nAddress, bool bIsBigEndian)
{
    quint16 nResult=0;

    read_array(hProcess,nAddress,(char *)&nResult,2);

    if(bIsBigEndian)
    {
        nResult=qFromBigEndian(nResult);
    }
    else
    {
        nResult=qFromLittleEndian(nResult);
    }

    return nResult;
}

quint32 XProcess::read_uint32(void *hProcess, qint64 nAddress, bool bIsBigEndian)
{
    quint32 nResult=0;

    read_array(hProcess,nAddress,(char *)&nResult,4);

    if(bIsBigEndian)
    {
        nResult=qFromBigEndian(nResult);
    }
    else
    {
        nResult=qFromLittleEndian(nResult);
    }

    return nResult;
}

quint64 XProcess::read_uint64(void *hProcess, qint64 nAddress, bool bIsBigEndian)
{
    quint64 nResult=0;

    read_array(hProcess,nAddress,(char *)&nResult,8);

    if(bIsBigEndian)
    {
        nResult=qFromBigEndian(nResult);
    }
    else
    {
        nResult=qFromLittleEndian(nResult);
    }

    return nResult;
}

void XProcess::write_uint8(void *hProcess, qint64 nAddress, quint8 nValue)
{
    write_array(hProcess,nAddress,(char *)&nValue,1);
}

void XProcess::write_uint16(void *hProcess, qint64 nAddress, quint16 nValue, bool bIsBigEndian)
{
    if(bIsBigEndian)
    {
        nValue=qFromBigEndian(nValue);
    }
    else
    {
        nValue=qFromLittleEndian(nValue);
    }

    write_array(hProcess,nAddress,(char *)&nValue,2);
}

void XProcess::write_uint32(void *hProcess, qint64 nAddress, quint32 nValue, bool bIsBigEndian)
{
    if(bIsBigEndian)
    {
        nValue=qFromBigEndian(nValue);
    }
    else
    {
        nValue=qFromLittleEndian(nValue);
    }

    write_array(hProcess,nAddress,(char *)&nValue,4);
}

void XProcess::write_uint64(void *hProcess, qint64 nAddress, quint64 nValue, bool bIsBigEndian)
{
    if(bIsBigEndian)
    {
        nValue=qFromBigEndian(nValue);
    }
    else
    {
        nValue=qFromLittleEndian(nValue);
    }

    write_array(hProcess,nAddress,(char *)&nValue,8);
}

qint64 XProcess::read_array(void *hProcess, qint64 nAddress, char *pData, qint64 nSize)
{
    qint64 nResult=0;
#ifdef Q_OS_WIN
    SIZE_T _nSize=0;

    if(ReadProcessMemory(hProcess,(LPVOID *)nAddress,pData,(SIZE_T)nSize,&_nSize))
    {
        nResult=(qint64)_nSize;
    }
#endif
    return nResult;
}

qint64 XProcess::write_array(void *hProcess, qint64 nAddress, char *pData, qint64 nSize)
{
    qint64 nResult=0;
#ifdef Q_OS_WIN
    SIZE_T _nSize=0;

    if(WriteProcessMemory(hProcess,(LPVOID *)nAddress,pData,(SIZE_T)nSize,&_nSize))
    {
        nResult=(qint64)_nSize;
    }
#endif
    return nResult;
}

QByteArray XProcess::read_array(void *hProcess, qint64 nAddress, qint32 nSize)
{
    QByteArray baResult;

    baResult.resize(nSize);
    // TODO Check if fails
    read_array(hProcess,nAddress,baResult.data(),nSize);

    return baResult;
}

QString XProcess::read_ansiString(void *hProcess, qint64 nAddress, qint64 nMaxSize)
{
    char *pBuffer=new char[nMaxSize+1];
    QString sResult;
    qint32 i=0;

    for(;i<nMaxSize;i++)
    {
        if(!read_array(hProcess,nAddress+i,&(pBuffer[i]),1))
        {
            break;
        }

        if(pBuffer[i]==0)
        {
            break;
        }
    }

    pBuffer[i]=0;
    sResult.append(pBuffer);

    delete [] pBuffer;

    return sResult;
}

QString XProcess::read_unicodeString(void *hProcess, qint64 nAddress, qint64 nMaxSize)
{
    QString sResult;

    if(nMaxSize)
    {
        quint16 *pBuffer=new quint16[nMaxSize+1];

        for(qint32 i=0;i<nMaxSize;i++)
        {
            pBuffer[i]=read_uint16(hProcess,nAddress+2*i);

            if(pBuffer[i]==0)
            {
                break;
            }

            if(i==nMaxSize-1)
            {
                pBuffer[nMaxSize]=0;
            }
        }

        sResult=QString::fromUtf16(pBuffer);

        delete [] pBuffer;
    }

    return sResult;
}
#ifdef Q_OS_WIN
qint64 XProcess::getTEBAddress(qint64 nThreadID)
{
    qint64 nResult=0;

    void *pThread=openThread(nThreadID);

    if(pThread)
    {
        nResult=getTEBAddress(pThread);

        closeProcess(pThread);
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getTEBAddress(void *hThread)
{
    qint64 nResult=-1;

    HMODULE hNtDll=LoadLibrary(TEXT("ntdll.dll"));
    if(hNtDll)
    {
        S_THREAD_BASIC_INFORMATION tbi={};

        pfnNtQueryInformationThread gNtQueryInformationThread=(pfnNtQueryInformationThread)GetProcAddress(hNtDll,"NtQueryInformationThread");

        if(gNtQueryInformationThread)
        {
            LONG nTemp=0;
            gNtQueryInformationThread(hThread,(THREADINFOCLASS)0,&tbi,sizeof(tbi),(PULONG)&nTemp); // mb TODO error handle
            nResult=(qint64)tbi.TebBaseAddress;
        }
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getPEBAddress(qint64 nProcessID)
{
    qint64 nResult=0;

    void *pProcess=openProcess(nProcessID);

    if(pProcess)
    {
        nResult=getPEBAddress(pProcess);

        closeProcess(pProcess);
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getPEBAddress(void *hProcess)
{
    qint64 nResult=-1;

    HMODULE hNtDll=LoadLibrary(TEXT("ntdll.dll"));
    if(hNtDll)
    {
        S_PROCESS_BASIC_INFORMATION pbi={};

        pfnNtQueryInformationProcess gNtQueryInformationProcess=(pfnNtQueryInformationProcess)GetProcAddress(hNtDll,"NtQueryInformationProcess");

        if(gNtQueryInformationProcess)
        {
            LONG nTemp=0;
            if(gNtQueryInformationProcess(hProcess,ProcessBasicInformation,&pbi,sizeof(pbi),(PULONG)&nTemp)==ERROR_SUCCESS)
            {
                nResult=(qint64)pbi.PebBaseAddress;
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

    QList<qint64> listThreadIDs=getThreadIDsList(nProcessID);

    qint32 nNumberOfThreads=listThreadIDs.count();

    for(qint32 i=0;i<nNumberOfThreads;i++)
    {
        qint64 nThreadID=getTEBAddress(listThreadIDs.at(i));

        listResult.append(nThreadID);
    }

    return listResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getProcessIDByHandle(void *hProcess)
{
    qint64 nResult=0;

    nResult=GetProcessId(hProcess);

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getThreadIDByHandle(void *hThread)
{
    qint64 nResult=0;

    nResult=GetThreadId(hThread);

    return nResult;
}
#endif

XBinary::OSINFO XProcess::getOsInfo()
{
    XBinary::OSINFO result={};
#ifdef Q_OS_WIN

    result.osName=XBinary::OSNAME_WINDOWS;
    // TODO OS Version

    OSVERSIONINFOEXA ovi={};

    ovi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEXA);

    GetVersionExA((OSVERSIONINFOA *)&ovi);

    result.sBuild=QString("%1.%2.%3").arg(QString::number(ovi.dwMajorVersion),
                                          QString::number(ovi.dwMinorVersion),
                                          QString::number(ovi.dwBuildNumber));

    SYSTEM_INFO si={};
    GetSystemInfo(&si);

    if      (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL)       result.sArch="I386";
    else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)       result.sArch="AMD64";
    else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_IA64)        result.sArch="IA64";
    else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM)         result.sArch="ARM";
    else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64)       result.sArch="ARM64";
#endif

    if(sizeof(char *)==8)
    {
        result.mode=XBinary::MODE_64;
    }
    else
    {
        result.mode=XBinary::MODE_32;
    }

    return result;
}
