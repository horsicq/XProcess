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
#include "xprocess.h"

XProcess::XProcess(QObject *pParent) : QObject(pParent)
{

}

QList<XProcess::PROCESS_INFO> XProcess::getProcessesList()
{
    QList<PROCESS_INFO> listResult;
#ifdef Q_OS_WIN
    HANDLE hProcesses=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

    if(hProcesses!=INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe32={};
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

bool XProcess::setPrivilege(QString sName,bool bEnable)
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
            TOKEN_PRIVILEGES tp={};

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

QList<XBinary::MEMORY_REGION> XProcess::getMemoryRegionsList(void *hProcess,quint64 nAddress,quint64 nSize)
{
    QList<XBinary::MEMORY_REGION> listResult;
#ifdef Q_OS_WIN
    for(quint64 nCurrentAddress=nAddress;nCurrentAddress<nAddress+nSize;)
    {
        nCurrentAddress=S_ALIGN_DOWN(nCurrentAddress,0x1000);

        MEMORY_BASIC_INFORMATION mbi={};

        if(VirtualQueryEx(hProcess,(LPCVOID)nCurrentAddress,&mbi,sizeof(mbi))==sizeof(mbi))
        {
            XBinary::MEMORY_REGION memoryRegion={};

            memoryRegion.nType=mbi.Type;

            if(memoryRegion.nType)
            {
                memoryRegion.nAddress=(qint64)mbi.BaseAddress;
                memoryRegion.nSize=(qint64)mbi.RegionSize;
                memoryRegion.mf=protectToFlags(mbi.Protect);
                memoryRegion.nAllocationBase=(qint64)mbi.AllocationBase;
                memoryRegion.mfAllocation=protectToFlags(mbi.AllocationProtect);
                memoryRegion.nState=mbi.State;

                listResult.append(memoryRegion);
            }

            nCurrentAddress+=(quint64)mbi.RegionSize;
        }
        else
        {
            break;
        }
    }
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=static_cast<QFile *>(hProcess);

    if(pFile)
    {
        QByteArray baData=pFile->readAll();

        QTextStream inStream(baData,QIODevice::ReadOnly);

        while(!inStream.atEnd())
        {
            QString sRecord=inStream.readLine();

            QString sAddress=sRecord.section(" ",0,0);
            QString sFlags=sRecord.section(" ",1,1);
            QString sOffset=sRecord.section(" ",2,2);
            QString sDevice=sRecord.section(" ",3,3);
            QString sFileNumber=sRecord.section(" ",4,4);
            QString sPathName=sRecord.section(" ",5,-1).trimmed();

            XBinary::MEMORY_REGION memoryRegion={};

            memoryRegion.nAddress=sAddress.section("-",0,0).toULongLong(0,16);
            memoryRegion.nSize=sAddress.section("-",1,1).toULongLong(0,16)-memoryRegion.nAddress;

            if((memoryRegion.nAddress>=nAddress)&&(nAddress+nSize>=memoryRegion.nAddress+memoryRegion.nSize))
            {
                memoryRegion.mf.bExecute=sFlags.contains("x");
                memoryRegion.mf.bRead=sFlags.contains("r");
                memoryRegion.mf.bWrite=sFlags.contains("w");
                memoryRegion.mf.bPrivate=sFlags.contains("p");
                memoryRegion.mf.bShare=sFlags.contains("s");
                memoryRegion.nOffset=sOffset.toLongLong(0,16);
                memoryRegion.sDevice=sDevice;
                memoryRegion.nFile=sFileNumber.toLongLong(0,10);
                memoryRegion.sFileName=sPathName;

                listResult.append(memoryRegion);
            }
        }
    }

#endif
    return listResult;
}

QList<XBinary::MEMORY_REGION> XProcess::getMemoryRegionsList(qint64 nProcessID,quint64 nAddress,quint64 nSize)
{
    QList<XBinary::MEMORY_REGION> listResult;

    void *pProcess=openMemoryQuery(nProcessID); // TODO OpenMemoryQuery QFile for linux

    if(pProcess)
    {
        listResult=getMemoryRegionsList(pProcess,nAddress,nSize);

        closeMemoryQuery(pProcess); // TODO CloseMemoryQuery
    }

    return listResult;
}

QList<XBinary::MEMORY_REGION> XProcess::getMemoryRegionsList(HANDLEID handleID,quint64 nAddress,quint64 nSize)
{
    QList<XBinary::MEMORY_REGION> listResult;

    if(handleID.hHandle)
    {
        listResult=getMemoryRegionsList(handleID.hHandle,nAddress,nSize);
    }
    else if(handleID.nID)
    {
        handleID.hHandle=XProcess::openMemoryQuery(handleID.nID);

        if(handleID.hHandle)
        {
            listResult=getMemoryRegionsList(handleID,nAddress,nSize);

            XProcess::closeMemoryQuery(handleID.hHandle);
        }
    }

    return listResult;
}

XBinary::MEMORY_REGION XProcess::getMemoryRegion(void *hProcess, quint64 nAddress)
{
    // TODO LINUX
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
        result.mf=protectToFlags(mbi.Protect);
    }

//    // TODO Check
//    if(result.nSize>0x10000)
//    {
//        result.nSize=0x10000;
//    }
#endif
#ifdef Q_OS_LINUX
    QList<XBinary::MEMORY_REGION> listRecords=getMemoryRegionsList(hProcess,0,0xFFFFFFFFFFFFFFFF);

    qint32 nNumberOfRecords=listRecords.count();

    for(qint32 i=0;i<nNumberOfRecords;i++)
    {
        if((nAddress>=listRecords.at(i).nAddress)&&(nAddress<listRecords.at(i).nAddress+listRecords.at(i).nSize))
        {
            result=listRecords.at(i);

            break;
        }
    }

#endif
    return result;
}

XBinary::MEMORY_REGION XProcess::getMemoryRegion(qint64 nProcessID, quint64 nAddress)
{
    XBinary::MEMORY_REGION result={};

    void *pProcess=openMemoryQuery(nProcessID);

    if(pProcess)
    {
        result=getMemoryRegion(pProcess,nAddress);

        closeMemoryQuery(pProcess);
    }

    return result;
}

XBinary::MEMORY_REGION XProcess::getMemoryRegion(HANDLEID handleID, quint64 nAddress)
{
    XBinary::MEMORY_REGION mrResult={};

    if(handleID.hHandle)
    {
        mrResult=getMemoryRegion(handleID.hHandle,nAddress);
    }
    else if(handleID.nID)
    {
        handleID.hHandle=XProcess::openMemoryQuery(handleID.nID);

        if(handleID.hHandle)
        {
            mrResult=getMemoryRegion(handleID,nAddress);

            XProcess::closeMemoryQuery(handleID.hHandle);
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

XBinary::MEMORY_FLAGS XProcess::protectToFlags(quint32 nValue)
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
        result.bExecute=true;
        result.bRead=true;
    }
    else if(nValue==PAGE_EXECUTE_READWRITE)
    {
        result.bExecute=true;
        result.bRead=true;
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
        result=protectToFlags(mbi.Protect);
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

void *XProcess::openMemoryQuery(qint64 nProcessID)
{
    void *pResult=0;
#ifdef Q_OS_WIN
    pResult=(void *)OpenProcess(PROCESS_ALL_ACCESS,0,nProcessID);
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=new QFile;
    pFile->setFileName(QString("/proc/%1/maps").arg(nProcessID));

    if(pFile->open(QIODevice::ReadOnly))
    {
        pResult=pFile;
    }
#endif
    return pResult;
}

void *XProcess::openMemoryIO(qint64 nProcessID)
{
    void *pResult=0;
#ifdef Q_OS_WIN
    pResult=(void *)OpenProcess(PROCESS_ALL_ACCESS,0,nProcessID);
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=new QFile;
    pFile->setFileName(QString("/proc/%1/mem").arg(nProcessID));

    if(XBinary::tryToOpen(pFile))
    {
        pResult=pFile;
    }
#endif
    return pResult;
}

void XProcess::closeProcess(void *hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hProcess);
#endif
}

void XProcess::closeMemoryQuery(void *hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hProcess);
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=static_cast<QFile *>(hProcess);

    if(pFile)
    {
        pFile->close();
    }
#endif
}

void XProcess::closeMemoryIO(void *hProcess)
{
#ifdef Q_OS_WIN
    CloseHandle((HANDLE)hProcess);
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=static_cast<QFile *>(hProcess);

    if(pFile)
    {
        pFile->close();
    }
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

    void *pProcessHandle=openMemoryIO(nProcessID);

    if(pProcessHandle)
    {
        bResult=true;

        closeMemoryIO(pProcessHandle);
    }

    return bResult;
}

quint8 XProcess::read_uint8(void *hProcess, quint64 nAddress)
{
    quint8 nResult=0;

    read_array(hProcess,nAddress,(char *)&nResult,1);

    return nResult;
}

quint16 XProcess::read_uint16(void *hProcess, quint64 nAddress, bool bIsBigEndian)
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

quint32 XProcess::read_uint32(void *hProcess,quint64 nAddress,bool bIsBigEndian)
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

quint64 XProcess::read_uint64(void *hProcess, quint64 nAddress, bool bIsBigEndian)
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

void XProcess::write_uint8(void *hProcess, quint64 nAddress, quint8 nValue)
{
    write_array(hProcess,nAddress,(char *)&nValue,1);
}

void XProcess::write_uint16(void *hProcess, quint64 nAddress, quint16 nValue, bool bIsBigEndian)
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

void XProcess::write_uint32(void *hProcess, quint64 nAddress, quint32 nValue, bool bIsBigEndian)
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

void XProcess::write_uint64(void *hProcess, quint64 nAddress, quint64 nValue, bool bIsBigEndian)
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

qint64 XProcess::read_array(void *hProcess, quint64 nAddress, char *pData, quint64 nSize)
{
    qint64 nResult=0;
#ifdef Q_OS_WIN
    SIZE_T _nSize=0;

    if(ReadProcessMemory(hProcess,(LPVOID *)nAddress,pData,(SIZE_T)nSize,&_nSize))
    {
        nResult=(qint64)_nSize;
    }
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=static_cast<QFile *>(hProcess);

    if(pFile)
    {
        pFile->seek(nAddress);
        nResult=pFile->read(pData,nSize);
    }
#endif
    return nResult;
}

qint64 XProcess::write_array(void *hProcess, quint64 nAddress, char *pData, quint64 nSize)
{
    qint64 nResult=0;
#ifdef Q_OS_WIN
    SIZE_T _nSize=0;

    if(WriteProcessMemory(hProcess,(LPVOID *)nAddress,pData,(SIZE_T)nSize,&_nSize))
    {
        nResult=(qint64)_nSize;
    }
#endif
#ifdef Q_OS_LINUX
    QFile *pFile=static_cast<QFile *>(hProcess);

    if(pFile)
    {
        if(pFile->isWritable())
        {
            pFile->seek(nAddress);
            nResult=pFile->write(pData,nSize);
            pFile->flush();
        }
    }
#endif
    return nResult;
}

QByteArray XProcess::read_array(void *hProcess, quint64 nAddress, quint64 nSize)
{
    QByteArray baResult;

    baResult.resize(nSize);
    // TODO Check if fails
    read_array(hProcess,nAddress,baResult.data(),nSize);

    return baResult;
}

QString XProcess::read_ansiString(void *hProcess, quint64 nAddress, quint64 nMaxSize)
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

QString XProcess::read_unicodeString(void *hProcess,quint64 nAddress,quint64 nMaxSize)
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
QList<XProcess::WINSYSHANDLE> XProcess::getOpenHandles(qint64 nProcessID)
{
    QList<XProcess::WINSYSHANDLE> listResult;

    HMODULE hNtDll=LoadLibrary(TEXT("ntdll.dll"));
    if(hNtDll)
    {
        pfnNtQuerySystemInformation gNtQuerySystemInformation=(pfnNtQuerySystemInformation)GetProcAddress(hNtDll,"NtQuerySystemInformation");

        if(gNtQuerySystemInformation)
        {
            qint32 nMemorySize=0x10000;
            void *pMemory=malloc(nMemorySize);

            NTSTATUS status=ERROR_SUCCESS;

            while(true)
            {
                XBinary::_zeroMemory((char *)pMemory,nMemorySize);

                status=gNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16,pMemory,nMemorySize,NULL);

                if(status!=0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
                {
                    break;
                }

                nMemorySize*=2;
                pMemory=realloc(pMemory,nMemorySize);
            }

            if(status==ERROR_SUCCESS)
            {
                S_SYSTEM_HANDLE_INFORMATION *pSHI=(S_SYSTEM_HANDLE_INFORMATION *)pMemory;

                for(qint32 i=0;i<(qint32)(pSHI->NumberOfHandles);i++)
                {
                    if((pSHI->Handles[i].UniqueProcessId==nProcessID)||(nProcessID==-1))
                    {
                        WINSYSHANDLE record={};

                        record.nProcessID=pSHI->Handles[i].UniqueProcessId;
                        record.nCreatorBackTraceIndex=pSHI->Handles[i].CreatorBackTraceIndex;
                        record.nHandle=pSHI->Handles[i].HandleValue;
                        record.nAccess=pSHI->Handles[i].GrantedAccess;
                        record.nFlags=pSHI->Handles[i].HandleAttributes;
                        record.nObjectAddress=(quint64)pSHI->Handles[i].Object;
                        record.nObjectTypeNumber=pSHI->Handles[i].ObjectTypeIndex;

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

    HMODULE hNtDll=LoadLibrary(TEXT("ntdll.dll"));
    if(hNtDll)
    {
        pfnNtQuerySystemInformation gNtQuerySystemInformation=(pfnNtQuerySystemInformation)GetProcAddress(hNtDll,"NtQuerySystemInformation");

        if(gNtQuerySystemInformation)
        {
            qint32 nMemorySize=0x10000;
            void *pMemory=malloc(nMemorySize);

            NTSTATUS status=ERROR_SUCCESS;

            while(true)
            {
                XBinary::_zeroMemory((char *)pMemory,nMemorySize);

                status=gNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x40,pMemory,nMemorySize,NULL);

                if(status!=0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
                {
                    break;
                }

                nMemorySize*=2;
                pMemory=realloc(pMemory,nMemorySize);
            }

            if(status==ERROR_SUCCESS)
            {
                S_SYSTEM_HANDLE_INFORMATION_EX *pSHI=(S_SYSTEM_HANDLE_INFORMATION_EX *)pMemory;

                for(qint32 i=0;i<(qint32)(pSHI->NumberOfHandles);i++)
                {
                    if((pSHI->Handles[i].UniqueProcessId==nProcessID)||(nProcessID==-1))
                    {
                        WINSYSHANDLE record={};

                        record.nProcessID=pSHI->Handles[i].UniqueProcessId;
                        record.nCreatorBackTraceIndex=pSHI->Handles[i].CreatorBackTraceIndex;
                        record.nHandle=pSHI->Handles[i].HandleValue;
                        record.nAccess=pSHI->Handles[i].GrantedAccess;
                        record.nFlags=pSHI->Handles[i].HandleAttributes;
                        record.nObjectAddress=(quint64)pSHI->Handles[i].Object;
                        record.nObjectTypeNumber=pSHI->Handles[i].ObjectTypeIndex;

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
    quint64 nResult=0;

    QList<XProcess::WINSYSHANDLE> listHandles=getOpenHandlesEx(4);

    qint32 nNumberOfRecords=listHandles.count();

    for(int i=0;i<nNumberOfRecords;i++)
    {
        if(listHandles.at(i).nObjectTypeNumber==7)
        {
            // Take the first
            nResult=listHandles.at(i).nObjectAddress;

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

    quint32 nLastError=GetLastError();

    if(nLastError)
    {
        LPWSTR messageBuffer=nullptr;

        size_t size=FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                                     NULL,nLastError,MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),(LPWSTR)&messageBuffer,0,NULL);

        sResult=QString::fromWCharArray(messageBuffer,size);

        LocalFree(messageBuffer);
    }

    return sResult;
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
    //else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64)       result.sArch="ARM64"; // TODO Macros
#endif
#ifdef Q_OS_LINUX
    result.osName=XBinary::OSNAME_LINUX;
    result.sArch="AMD64"; // TODO !!!
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

QList<XProcess::MODULE> XProcess::getModulesList(qint64 nProcessID)
{
    QList<XProcess::MODULE> listResult;

#ifdef Q_OS_WIN
    HANDLE hModules=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);

    if(hModules!=INVALID_HANDLE_VALUE)
    {
        tagMODULEENTRY32W me32={};
        me32.dwSize=sizeof(tagMODULEENTRY32W);

        if(Module32FirstW(hModules,&me32))
        {
            do
            {
                MODULE record={};

                record.nAddress=(qint64)me32.modBaseAddr;
                record.nSize=(qint64)me32.modBaseSize;
                record.sName=QString::fromWCharArray(me32.szModule);
                record.sFileName=QString::fromWCharArray(me32.szExePath);

                listResult.append(record);
            }
            while(Module32NextW(hModules,&me32));
        }

        CloseHandle(hModules);
    }
#endif
#ifdef Q_OS_LINUX
    QList<XBinary::MEMORY_REGION> listMR=getMemoryRegionsList(nProcessID,0,0xFFFFFFFFFFFFFFFF);

    qint32 nNumberOfRecords=listMR.count();

    QMap<QString,quint64> mapImageBase;
    QMap<QString,quint64> mapImageSize;

    for(qint32 i=0;i<nNumberOfRecords;i++)
    {
        if(listMR.at(i).nFile)
        {
            QString sFileName=listMR.at(i).sFileName;

            if(!(mapImageBase.value(sFileName)))
            {
                mapImageBase.insert(sFileName,listMR.at(i).nAddress);
            }

            mapImageSize.insert(sFileName,mapImageSize.value(sFileName)+listMR.at(i).nSize);
        }
    }

    QList<quint64> listImageBases=mapImageBase.values();

    std::sort(listImageBases.begin(),listImageBases.end());

    nNumberOfRecords=listImageBases.count();

    for(qint32 i=0;i<nNumberOfRecords;i++)
    {
        quint64 nImageBase=listImageBases.at(i);
        QString sFileName=mapImageBase.key(nImageBase);

        MODULE record={};

        record.nAddress=nImageBase;
        record.nSize=mapImageSize.value(sFileName);
        record.sName=QFileInfo(sFileName).fileName();
        record.sFileName=sFileName;

        listResult.append(record);
    }

#endif

    return listResult;
}
