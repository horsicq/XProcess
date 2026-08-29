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
#include "xprocessdevice.h"

#include <limits>

XProcessDevice::XProcessDevice(QObject *pParent) : QIODevice(pParent)
{
    g_hProcess = nullptr;
    g_nPID = 0;
    g_nAddress = 0;
    g_nSize = 0;
}

XProcessDevice::~XProcessDevice()
{
    if (isOpen()) {
        XProcessDevice::close();
    }
}

qint64 XProcessDevice::size() const
{
    return (g_nSize <= (quint64)(std::numeric_limits<qint64>::max)()) ? (qint64)g_nSize : -1;
}

bool XProcessDevice::isSequential() const
{
    return false;
}

bool XProcessDevice::seek(qint64 pos)
{
    return isOpen() && (pos >= 0) && (pos <= size()) && QIODevice::seek(pos);
}

bool XProcessDevice::reset()
{
    return seek(0);
}

bool XProcessDevice::open(QIODevice::OpenMode mode)
{
    Q_UNUSED(mode)

    return false;  // Use openPId or OpenHandle
}

bool XProcessDevice::atEnd() const
{
    const qint64 nPosition = pos();
    const qint64 nDeviceSize = size();

    return !isOpen() || (nPosition < 0) || (nDeviceSize < 0) || (nPosition >= nDeviceSize);
}

void XProcessDevice::close()
{
    if (isOpen()) {
        QIODevice::close();
    }

    if (g_nPID && g_hProcess) {
#ifdef Q_OS_WIN
        CloseHandle(g_hProcess);
#endif
#ifdef Q_OS_LINUX
        QFile *pFile = static_cast<QFile *>(g_hProcess);
        pFile->close();
        delete pFile;
#endif
    }

    g_hProcess = nullptr;
    g_nPID = 0;
}

qint64 XProcessDevice::pos() const
{
    return QIODevice::pos();
}

bool XProcessDevice::openPID(qint64 nPID, quint64 nAddress, quint64 nSize, QIODevice::OpenMode mode)
{
    if ((mode != ReadOnly) && (mode != WriteOnly) && (mode != ReadWrite)) return false;
    if ((nPID <= 0) || !nSize || (nSize > (quint64)(std::numeric_limits<qint64>::max)()) || (nAddress > ((std::numeric_limits<quint64>::max)() - (nSize - 1)))) {
        return false;
    }
#ifdef Q_OS_WIN
    if ((nAddress + nSize - 1) > (quint64)(std::numeric_limits<quintptr>::max)()) return false;
#elif defined(Q_OS_LINUX)
    if ((nAddress + nSize - 1) > (quint64)(std::numeric_limits<qint64>::max)()) return false;
#endif

    close();

    void *pProcess = nullptr;
#ifdef Q_OS_WIN
    quint32 nFlag = 0;

    if (mode == ReadOnly) {
        nFlag = PROCESS_VM_READ;
    } else if (mode == WriteOnly) {
        nFlag = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    } else {
        nFlag = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    }

    pProcess = OpenProcess(nFlag, 0, (DWORD)nPID);
#endif
#ifdef Q_OS_LINUX
    QIODevice::OpenModeFlag flag = QIODevice::NotOpen;

    if (mode == ReadOnly) {
        flag = QIODevice::ReadOnly;
    } else if (mode == WriteOnly) {
        flag = QIODevice::WriteOnly;
    } else {
        flag = QIODevice::ReadWrite;
    }

    QFile *pFile = new QFile;
    pFile->setFileName(QString("/proc/%1/mem").arg(nPID));
    if (pFile->open(flag)) {
        pProcess = pFile;
    } else {
        delete pFile;
    }
#endif

    if (!pProcess) return false;

    g_nPID = nPID;
    g_hProcess = pProcess;
    g_nAddress = nAddress;
    g_nSize = nSize;

    if (!QIODevice::open(mode) || !QIODevice::seek(0)) {
        close();
        return false;
    }

    return true;
}

bool XProcessDevice::openHandle(void *hProcess, quint64 nAddress, quint64 nSize, QIODevice::OpenMode mode)
{
    if ((mode != ReadOnly) && (mode != WriteOnly) && (mode != ReadWrite)) return false;
    if (!hProcess || !nSize || (nSize > (quint64)(std::numeric_limits<qint64>::max)()) || (nAddress > ((std::numeric_limits<quint64>::max)() - (nSize - 1)))) {
        return false;
    }
#ifdef Q_OS_WIN
    if ((nAddress + nSize - 1) > (quint64)(std::numeric_limits<quintptr>::max)()) {
        return false;
    }
#elif defined(Q_OS_LINUX)
    if ((nAddress + nSize - 1) > (quint64)(std::numeric_limits<qint64>::max)()) return false;
#endif

    close();

    g_hProcess = hProcess;
    g_nAddress = nAddress;
    g_nSize = nSize;
    if (!QIODevice::open(mode) || !QIODevice::seek(0)) {
        g_hProcess = nullptr;  // Borrowed handles must never be closed here.
        QIODevice::close();
        return false;
    }

    return true;
}

quint64 XProcessDevice::adjustSize(quint64 nSize)
{
    qint64 nPos = pos();
    if ((nPos < 0) || (nPos > size())) return 0;
    quint64 _nSize = 0x1000 - ((quint64)nPos % 0x1000);

    _nSize = qMin(_nSize, g_nSize - (quint64)nPos);
    quint64 nResult = qMin(nSize, _nSize);

    return nResult;
}
#ifdef Q_OS_WIN
void XProcessDevice::checkWindowsLastError()
{
    quint32 nLastErrorCode = GetLastError();

    if (nLastErrorCode) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, nLastErrorCode,
                                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, nullptr);

        setErrorString(QString("%1: ").arg(nLastErrorCode, 0, 16) + QString::fromUtf8((char *)messageBuffer, (int)size));

        // Free the buffer.
        LocalFree(messageBuffer);
    }
}
#endif
qint64 XProcessDevice::readData(char *pData, qint64 nMaxSize)
{
    const qint64 nPosition = pos();
    if (!isOpen() || !isReadable() || !g_hProcess || (nMaxSize < 0) || ((nMaxSize > 0) && !pData) || (nPosition < 0) || (nPosition > size())) {
        return -1;
    }

    nMaxSize = qMin(nMaxSize, size() - nPosition);
    if (!nMaxSize) return 0;

    qint64 nResult = 0;
    qint64 nCurrentPosition = nPosition;

    while (nResult < nMaxSize) {
        qint64 nDelta = N_BUFFER_SIZE - (nCurrentPosition % N_BUFFER_SIZE);
        nDelta = qMin(nDelta, nMaxSize - nResult);

        qint64 nTransferred = -1;
#ifdef Q_OS_WIN
        SIZE_T nRead = 0;
        if (ReadProcessMemory(g_hProcess, reinterpret_cast<LPCVOID>((quintptr)(g_nAddress + (quint64)nCurrentPosition)), pData, (SIZE_T)nDelta, &nRead)) {
            nTransferred = (qint64)nRead;
        } else {
            checkWindowsLastError();
        }
#elif defined(Q_OS_LINUX)
        QFile *pFile = static_cast<QFile *>(g_hProcess);
        if (pFile->seek((qint64)(g_nAddress + (quint64)nCurrentPosition))) {
            nTransferred = pFile->read(pData, nDelta);
        }
#endif

        if (nTransferred <= 0) return nResult ? nResult : -1;
        if (nTransferred > nDelta) return nResult ? nResult : -1;

        nCurrentPosition += nTransferred;
        pData += nTransferred;
        nResult += nTransferred;
        if (nTransferred != nDelta) break;
    }

#ifdef QT_DEBUG
    QString sErrorString = errorString();
    if ((sErrorString != "") && (sErrorString != "Unknown error")) {
        qDebug("%s", sErrorString.toLatin1().data());
    }
#endif

    return nResult;
}

qint64 XProcessDevice::writeData(const char *pData, qint64 nMaxSize)
{
    const qint64 nPosition = pos();
    if (!isOpen() || !isWritable() || !g_hProcess || (nMaxSize < 0) || ((nMaxSize > 0) && !pData) || (nPosition < 0) || (nPosition > size())) {
        return -1;
    }

    nMaxSize = qMin(nMaxSize, size() - nPosition);
    if (!nMaxSize) return 0;

    qint64 nResult = 0;
    qint64 nCurrentPosition = nPosition;

    while (nResult < nMaxSize) {
        qint64 nDelta = N_BUFFER_SIZE - (nCurrentPosition % N_BUFFER_SIZE);
        nDelta = qMin(nDelta, nMaxSize - nResult);

        qint64 nTransferred = -1;
#ifdef Q_OS_WIN
        SIZE_T nWritten = 0;
        if (WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>((quintptr)(g_nAddress + (quint64)nCurrentPosition)), pData, (SIZE_T)nDelta, &nWritten)) {
            nTransferred = (qint64)nWritten;
        } else {
            checkWindowsLastError();
        }
#elif defined(Q_OS_LINUX)
        QFile *pFile = static_cast<QFile *>(g_hProcess);
        if (pFile->seek((qint64)(g_nAddress + (quint64)nCurrentPosition))) {
            nTransferred = pFile->write(pData, nDelta);
        }
#endif

        if (nTransferred <= 0) return nResult ? nResult : -1;
        if (nTransferred > nDelta) return nResult ? nResult : -1;

        nCurrentPosition += nTransferred;
        pData += nTransferred;
        nResult += nTransferred;
        if (nTransferred != nDelta) break;
    }

#ifdef QT_DEBUG
    QString sErrorString = errorString();
    if ((sErrorString != "") && (sErrorString != "Unknown error")) {
        qDebug("%s", sErrorString.toLatin1().data());
    }
#endif

    return nResult;
}

void XProcessDevice::setErrorString(const QString &str)
{
    QIODevice::setErrorString(str);
}
