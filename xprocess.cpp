// copyright (c) 2019-2020 hors<horsicq@gmail.com>
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
#ifdef Q_OS_WIN
QList<XProcess::MEMORY_REGION> XProcess::getMemoryRegionsList(HANDLE hProcess, qint64 nAddress, qint32 nSize)
{
    QList<XProcess::MEMORY_REGION> listResult;

    for(qint64 nCurrentAddress=nAddress;nCurrentAddress<nAddress+nSize;)
    {
        nCurrentAddress=X_ALIGN_DOWN(nCurrentAddress,0x1000);

        MEMORY_BASIC_INFORMATION mbi={};

        if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
        {
            MEMORY_REGION memoryRegion={};

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

    return listResult;
}
#endif
XProcess::PROCESS_INFO XProcess::getInfoByProcessID(qint64 nProcessID)
{
    PROCESS_INFO result= {0};
#ifdef Q_OS_WIN
    if(nProcessID)
    {
        HANDLE hModule=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,(DWORD)nProcessID);

        if(hModule!=INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 me32;
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
                result.sFilePath=list.at(0).data();

                if(result.sFilePath!="")
                {
                    QFileInfo fi(result.sFilePath);
                    result.sName=fi.baseName();

                    result.nID=nProcessID;
                }
            }

            file.close();
        }
    }
#endif
    return result;
}
#ifdef Q_OS_WIN
qint64 XProcess::getRegionAllocationSize(HANDLE hProcess,qint64 nRegionBase)
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
qint64 XProcess::getRegionAllocationBase(HANDLE hProcess, qint64 nAddress)
{
    qint64 nResult=-1;

    nAddress=X_ALIGN_DOWN(nAddress,0x1000);

    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        nResult=(qint64)mbi.AllocationBase;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionBase(HANDLE hProcess, qint64 nAddress)
{
    qint64 nResult=-1;

    nAddress=X_ALIGN_DOWN(nAddress,0x1000);

    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        nResult=(qint64)mbi.BaseAddress;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getRegionSize(HANDLE hProcess, qint64 nAddress)
{
    qint64 nResult=-1;

    nAddress=X_ALIGN_DOWN(nAddress,0x1000);

    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        nResult=(qint64)mbi.RegionSize;
    }

    return nResult;
}

XProcess::MEMORY_FLAGS XProcess::dwordToFlags(quint32 nValue)
{
    MEMORY_FLAGS result={};

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

    return result;
}
#endif
#ifdef Q_OS_WIN
XProcess::MEMORY_FLAGS XProcess::getMemoryFlags(HANDLE hProcess, qint64 nAddress)
{
    MEMORY_FLAGS result={};
    MEMORY_BASIC_INFORMATION mbi={};

    if(VirtualQueryEx(hProcess,(LPCVOID)nAddress,&mbi,sizeof(mbi)))
    {
        result=dwordToFlags(mbi.Protect);
    }

    return result;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::getFileNameByHandle(HANDLE hHandle)
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

    int nSize=GetLogicalDriveStringsW(0,0);

    if(nSize)
    {
        WCHAR wszNtBuffer[256];

        WCHAR *pwszBuffer=new WCHAR[nSize+1];

        nSize=GetLogicalDriveStringsW(nSize,pwszBuffer);

        for(int i=0;i<nSize;)
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
#ifdef Q_OS_WIN
bool XProcess::readData(HANDLE hProcess, qint64 nAddress, char *pBuffer, qint32 nBufferSize)
{
    bool bResult=false;

    SIZE_T nSize=0;

    if(ReadProcessMemory(hProcess,(LPVOID *)nAddress,pBuffer,(SIZE_T)nBufferSize,&nSize))
    {
        if(nSize==(SIZE_T)nBufferSize)
        {
            bResult=true;
        }
    }

    return bResult;
}
#endif
#ifdef Q_OS_WIN
bool XProcess::writeData(HANDLE hProcess, qint64 nAddress, char *pBuffer, qint32 nBufferSize)
{
    bool bResult=false;

    SIZE_T nSize=0;

    if(WriteProcessMemory(hProcess,(LPVOID *)nAddress,pBuffer,(SIZE_T)nBufferSize,&nSize))
    {
        if(nSize==(SIZE_T)nBufferSize)
        {
            bResult=true;
        }
    }

    return bResult;
}
#endif
#ifdef Q_OS_WIN
quint8 XProcess::read_uint8(HANDLE hProcess, qint64 nAddress)
{
    quint8 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,1);

    return nResult;
}
#endif
#ifdef Q_OS_WIN
quint16 XProcess::read_uint16(HANDLE hProcess, qint64 nAddress)
{
    quint16 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,2);

    return nResult;
}
#endif
#ifdef Q_OS_WIN
quint32 XProcess::read_uint32(HANDLE hProcess, qint64 nAddress)
{
    quint32 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,4);

    return nResult;
}
#endif
#ifdef Q_OS_WIN
quint64 XProcess::read_uint64(HANDLE hProcess, qint64 nAddress)
{
    quint64 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,8);

    return nResult;
}
#endif
#ifdef Q_OS_WIN
void XProcess::write_uint8(HANDLE hProcess, qint64 nAddress, quint8 nValue)
{
    writeData(hProcess,nAddress,(char *)&nValue,1);
}
#endif
#ifdef Q_OS_WIN
void XProcess::write_uint16(HANDLE hProcess, qint64 nAddress, quint16 nValue)
{
    writeData(hProcess,nAddress,(char *)&nValue,2);
}
#endif
#ifdef Q_OS_WIN
void XProcess::write_uint32(HANDLE hProcess, qint64 nAddress, quint32 nValue)
{
    writeData(hProcess,nAddress,(char *)&nValue,4);
}
#endif
#ifdef Q_OS_WIN
void XProcess::write_uint64(HANDLE hProcess, qint64 nAddress, quint64 nValue)
{
    writeData(hProcess,nAddress,(char *)&nValue,8);
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::read_array(HANDLE hProcess, qint64 nAddress, char *pData, qint64 nSize)
{
    qint64 nResult=0;

    SIZE_T _nSize=0;

    if(ReadProcessMemory(hProcess,(LPVOID *)nAddress,pData,(SIZE_T)nSize,&_nSize))
    {
        nResult=(qint64)_nSize;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::write_array(HANDLE hProcess, qint64 nAddress, char *pData, qint64 nSize)
{
    qint64 nResult=0;

    SIZE_T _nSize=0;

    if(WriteProcessMemory(hProcess,(LPVOID *)nAddress,pData,(SIZE_T)nSize,&_nSize))
    {
        nResult=(qint64)_nSize;
    }

    return nResult;
}
#endif
#ifdef Q_OS_WIN
QByteArray XProcess::read_array(HANDLE hProcess, qint64 nAddress, qint32 nSize)
{
    QByteArray baResult;

    baResult.resize(nSize);
    // TODO Check if fails
    readData(hProcess,nAddress,baResult.data(),nSize);

    return baResult;
}
#endif
#ifdef Q_OS_WIN
QString XProcess::read_ansiString(HANDLE hProcess, qint64 nAddress, qint64 nMaxSize)
{
    char *pBuffer=new char[nMaxSize+1];
    QString sResult;
    int i=0;

    for(; i<nMaxSize; i++)
    {
        if(!readData(hProcess,nAddress+i,&(pBuffer[i]),1))
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
#endif
#ifdef Q_OS_WIN
QString XProcess::read_unicodeString(HANDLE hProcess, qint64 nAddress, qint64 nMaxSize)
{
    QString sResult;

    if(nMaxSize)
    {
        quint16 *pBuffer=new quint16[nMaxSize+1];

        for(int i=0; i<nMaxSize; i++)
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
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getTEBAddress(HANDLE hThread)
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
qint64 XProcess::getPEBAddress(HANDLE hProcess)
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
bool XProcess::setPrivilege(QString sName, bool bEnable)
{
    bool bResult=false;
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

    return bResult;
}
#endif
#ifdef Q_OS_WIN
qint64 XProcess::getProcessIDByHandle(HANDLE hProcess)
{
    qint64 nResult=0;

    nResult=GetProcessId(hProcess);

    return nResult;
}

qint64 XProcess::getThreadIDByHandle(HANDLE hThread)
{
    qint64 nResult=0;

    nResult=GetThreadId(hThread);

    return nResult;
}
#endif
