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
            quint64 nPID=fi.baseName().toUInt();

            PROCESS_INFO processInfo=getInfoByPID(nPID);

            if(processInfo.nID)
            {
                listResult.append(processInfo);
            }
        }
    }
#endif

    return listResult;
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
    if(nPID)
    {
        QFile file;
        file.setFileName(QString("/proc/%1/cmdline").arg(nPID));
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

                    result.nID=nPID;
                }
            }

            file.close();
        }
    }

#endif
    return result;
}

qint64 XProcess::getImageSize(HANDLE hProcess,qint64 nImageBase)
{
    qint64 nResult=0;

    qint64 _nAddress=nImageBase;
    while(true)
    {
        MEMORY_BASIC_INFORMATION mbi={};
        if(!VirtualQueryEx(hProcess,(LPCVOID)_nAddress,&mbi,sizeof(mbi)))
        {
            break;
        }
        if((mbi.RegionSize)&&((qint64)mbi.AllocationBase==nImageBase))
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

QString XProcess::getFileNameByHandle(HANDLE hHandle)
{
    QString sResult;

    HANDLE hFileMapping=CreateFileMappingW(hHandle,nullptr,PAGE_READONLY,NULL,GetFileSize(hHandle,nullptr),nullptr);

    if(hFileMapping)
    {
        void *pMem=MapViewOfFile(hFileMapping,FILE_MAP_READ,NULL,NULL,NULL);

        if(pMem)
        {
            WCHAR wszBuffer[1024];
            if(GetMappedFileNameW(GetCurrentProcess(),pMem,wszBuffer,sizeof(wszBuffer)))
            {
                sResult=QString::fromUtf16((ushort *)wszBuffer);
            }

            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMapping);
    }

    return sResult;
}

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

quint8 XProcess::read_uint8(HANDLE hProcess, qint64 nAddress)
{
    quint8 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,1);

    return nResult;
}

quint16 XProcess::read_uint16(HANDLE hProcess, qint64 nAddress)
{
    quint16 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,2);

    return nResult;
}

quint32 XProcess::read_uint32(HANDLE hProcess, qint64 nAddress)
{
    quint32 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,4);

    return nResult;
}

quint64 XProcess::read_uint64(HANDLE hProcess, qint64 nAddress)
{
    quint64 nResult=0;

    readData(hProcess,nAddress,(char *)&nResult,8);

    return nResult;
}

QByteArray XProcess::readArray(HANDLE hProcess, qint64 nAddress, qint32 nSize)
{
    QByteArray baResult;

    baResult.resize(nSize);

    readData(hProcess,nAddress,baResult.data(),nSize);

    return baResult;
}

#ifdef Q_OS_WIN
bool XProcess::setPrivilege(char *pszName, bool bEnable)
{
    bool bResult=false;
    HANDLE hToken;

    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
    {
        LUID SeValue;
        if(LookupPrivilegeValueA(nullptr,pszName,&SeValue))
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
