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
#include "xprocessdevice.h"

XProcessDevice::XProcessDevice(HANDLE hProcess, qint64 __nAddress, qint64 __nSize, QObject *parent)
{
    Q_UNUSED(parent);

    this->hProcess=hProcess;
    this->__nAddress=__nAddress;
    this->__nSize=__nSize;
}

XProcessDevice::~XProcessDevice()
{
    if(isOpen())
    {
        close();
    }
}

qint64 XProcessDevice::size() const
{
    return __nSize;
}

bool XProcessDevice::isSequential() const
{
    return false;
}

bool XProcessDevice::seek(qint64 pos)
{
    if((pos<(qint64)__nSize)&&(pos>=0))
    {
        QIODevice::seek(pos);
        return true;
    }

    return false;
}

bool XProcessDevice::reset()
{
    return seek(0);
}

bool XProcessDevice::open(QIODevice::OpenMode mode)
{
    bool bResult=true;

    if(bResult)
    {
        setOpenMode(mode);
    }

    return bResult;
}

bool XProcessDevice::atEnd()
{
    return (bytesAvailable()==0);
}

void XProcessDevice::close()
{
    setOpenMode(NotOpen);
}

qint64 XProcessDevice::pos()
{
    return QIODevice::pos();
}

qint64 XProcessDevice::adjustSize(qint64 nSize)
{
    qint64 nPos=pos();
    qint64 _nSize=X_ALIGN_UP(nPos,0x1000)-nPos;
    if(_nSize==0)
    {
        _nSize=0x1000;
    }
    _nSize=qMin(_nSize,(qint64)(__nSize-nPos));
    qint64 nResult=qMin(nSize,_nSize);

    return nResult;
}

qint64 XProcessDevice::readData(char *data, qint64 maxSize)
{
    qint64 nResult=0;

    qint64 _nPos=pos();

    maxSize=qMin(maxSize,(qint64)(__nSize-_nPos));

    for(qint64 i=0;i<maxSize;)
    {
        qint64 nDelta=X_ALIGN_UP(_nPos,0x1000)-_nPos;
        if(nDelta==0)
        {
            nDelta=0x1000;
        }
        nDelta=qMin(nDelta,(qint64)(maxSize-i));
        SIZE_T nSize=0;
        if(!ReadProcessMemory(hProcess,(LPVOID *)(_nPos+__nAddress),data,nDelta,&nSize))
        {
            break;
        }
        if(nSize!=nDelta)
        {
            break;
        }
        _nPos+=nDelta;
        data+=nDelta;
        nResult+=nDelta;
        i+=nDelta;
    }

    return nResult;
}

qint64 XProcessDevice::writeData(const char *data, qint64 maxSize)
{
    qint64 nResult=0;

    qint64 _nPos=pos();

    maxSize=qMin(maxSize,(qint64)(__nSize-_nPos));

    for(qint64 i=0;i<maxSize;)
    {
        qint64 nDelta=X_ALIGN_UP(_nPos,0x1000)-_nPos;
        if(nDelta==0)
        {
            nDelta=0x1000;
        }
        nDelta=qMin(nDelta,(qint64)(maxSize-i));
        SIZE_T nSize=0;
        if(!WriteProcessMemory(hProcess,(LPVOID *)(_nPos+__nAddress),data,nDelta,&nSize))
        {
            break;
        }
        if(nSize!=nDelta)
        {
            break;
        }
        _nPos+=nDelta;
        data+=nDelta;
        nResult+=nDelta;
        i+=nDelta;
    }

    return nResult;
}

void XProcessDevice::setErrorString(const QString &str)
{
    QIODevice::setErrorString(str);
}
