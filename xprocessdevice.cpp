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
#include "xprocessdevice.h"

XProcessDevice::XProcessDevice(QObject *parent) :
    QIODevice(parent)
{
#ifdef Q_OS_WIN
    g_hProcess=nullptr;
    g_nPID=0;
    g_nAddress=0;
    g_nSize=0;
#endif
}

XProcessDevice::~XProcessDevice()
{
    if(isOpen())
    {
        XProcessDevice::close();
    }
}

qint64 XProcessDevice::size() const
{
    return g_nSize;
}

bool XProcessDevice::isSequential() const
{
    return false;
}

bool XProcessDevice::seek(qint64 pos)
{
    bool bResult=false;

    if((pos<(qint64)g_nSize)&&(pos>=0))
    {
        bResult=QIODevice::seek(pos);
    }

    return bResult;
}

bool XProcessDevice::reset()
{
    return seek(0);
}

bool XProcessDevice::open(QIODevice::OpenMode mode)
{
    Q_UNUSED(mode)

    return false; // Use openPId or OpenHandle
}

bool XProcessDevice::atEnd() const
{
    return (bytesAvailable()==0);
}

void XProcessDevice::close()
{
    bool bSuccess=true;
#ifdef Q_OS_WIN
    if(g_nPID)
    {
        bSuccess=CloseHandle(g_hProcess);
    }
#endif
    if(bSuccess)
    {
        setOpenMode(NotOpen);
    }
}

qint64 XProcessDevice::pos() const
{
    return QIODevice::pos();
}

bool XProcessDevice::openPID(qint64 nPID, qint64 __nAddress, qint64 __nSize, QIODevice::OpenMode mode)
{
    bool bResult=true;

    setOpenMode(mode);

    this->g_nPID=nPID;
    this->g_nAddress=__nAddress;
    this->g_nSize=__nSize;

    quint32 nFlags=0;

#ifdef Q_OS_WIN
    if(mode==ReadOnly)
    {
        nFlags=PROCESS_VM_READ;
    }
    else if(mode==WriteOnly)
    {
        nFlags=PROCESS_VM_WRITE;
    }
    else if(mode==ReadWrite)
    {
        nFlags=PROCESS_ALL_ACCESS;
    }

    g_hProcess=OpenProcess(nFlags,0,(DWORD)nPID);

    bResult=(g_hProcess!=nullptr);
#endif

    return bResult;
}
#ifdef Q_OS_WIN
bool XProcessDevice::openHandle(HANDLE hProcess, qint64 __nAddress, qint64 __nSize, QIODevice::OpenMode mode)
{
    this->g_hProcess=hProcess;
    this->g_nAddress=__nAddress;
    this->g_nSize=__nSize;

    setOpenMode(mode);
    this->g_hProcess=hProcess;

    return true;
}
#endif
qint64 XProcessDevice::adjustSize(qint64 nSize)
{
    qint64 nPos=pos();
    qint64 _nSize=X_ALIGN_UP(nPos,0x1000)-nPos;

    if(_nSize==0)
    {
        _nSize=0x1000;
    }

    _nSize=qMin(_nSize,(qint64)(g_nSize-nPos));
    qint64 nResult=qMin(nSize,_nSize);

    return nResult;
}
#ifdef Q_OS_WIN
void XProcessDevice::checkWindowsLastError()
{
    quint32 nLastErrorCode=GetLastError();

    if(nLastErrorCode)
    {
        LPSTR messageBuffer=nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr, nLastErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, nullptr);

        setErrorString(QString("%1: ").arg(nLastErrorCode,0,16)+QString::fromUtf8((char *)messageBuffer,size));

        //Free the buffer.
        LocalFree(messageBuffer);
    }
}
#endif
qint64 XProcessDevice::readData(char *data, qint64 maxSize)
{
    qint64 nResult=0;

    qint64 _nPos=pos();

    maxSize=qMin(maxSize,(qint64)(g_nSize-_nPos));

    for(qint64 i=0; i<maxSize;)
    {
        qint64 nDelta=X_ALIGN_UP(_nPos,N_BUFFER_SIZE)-_nPos;

        if(nDelta==0)
        {
            nDelta=N_BUFFER_SIZE;
        }

        nDelta=qMin(nDelta,(qint64)(maxSize-i));
#ifdef Q_OS_WIN
        SIZE_T nSize=0;

        if(!ReadProcessMemory(g_hProcess,(LPVOID *)(_nPos+g_nAddress),data,(SIZE_T)nDelta,&nSize))
        {
            break;
        }

        if(nSize!=(SIZE_T)nDelta)
        {
            break;
        }

#endif
#ifdef Q_OS_LINUX
        break;
#endif
        _nPos+=nDelta;
        data+=nDelta;
        nResult+=nDelta;
        i+=nDelta;
    }

#ifdef Q_OS_WIN
    checkWindowsLastError();
#endif
    return nResult;
}

qint64 XProcessDevice::writeData(const char *data, qint64 maxSize)
{
    qint64 nResult=0;

    qint64 _nPos=pos();

    maxSize=qMin(maxSize,(qint64)(g_nSize-_nPos));

    for(qint64 i=0; i<maxSize;)
    {
        qint64 nDelta=X_ALIGN_UP(_nPos,N_BUFFER_SIZE)-_nPos;

        if(nDelta==0)
        {
            nDelta=N_BUFFER_SIZE;
        }

        nDelta=qMin(nDelta,(qint64)(maxSize-i));
#ifdef Q_OS_WIN
        SIZE_T nSize=0;

        if(!WriteProcessMemory(g_hProcess,(LPVOID *)(_nPos+g_nAddress),data,(SIZE_T)nDelta,&nSize))
        {
            break;
        }

        if(nSize!=(SIZE_T)nDelta)
        {
            break;
        }

#endif
#ifdef Q_OS_LINUX
        break; // TODO !!!
#endif
        _nPos+=nDelta;
        data+=nDelta;
        nResult+=nDelta;
        i+=nDelta;
    }

#ifdef Q_OS_WIN
    checkWindowsLastError();
#endif
    return nResult;
}

void XProcessDevice::setErrorString(const QString &str)
{
    QIODevice::setErrorString(str);
}
