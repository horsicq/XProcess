/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
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
#ifndef XPROCESSDEVICE_H
#define XPROCESSDEVICE_H

#include <QIODevice>
#include <QObject>
#ifdef Q_OS_WIN
#include <Windows.h>
#include <winternl.h>
#include <Tlhelp32.h>
#endif
#ifdef Q_OS_LINUX
#include <QFile>
#endif

#define X_ALIGN_DOWN(x, align) ((x) & ~(align - 1))
#define X_ALIGN_UP(x, align) (((x) & (align - 1)) ? X_ALIGN_DOWN(x, align) + align : x)

class XProcessDevice : public QIODevice {
    Q_OBJECT

public:
    explicit XProcessDevice(QObject *pParent = nullptr);
    ~XProcessDevice();

    virtual qint64 size() const;
    virtual bool isSequential() const;
    virtual bool seek(qint64 pos);
    virtual bool reset();
    virtual bool open(OpenMode mode);
    virtual bool atEnd() const;
    virtual void close();
    virtual qint64 pos() const;
    bool openPID(qint64 nPID, quint64 nAddress, quint64 nSize, OpenMode mode);
    bool openHandle(void *hProcess, quint64 nAddress, quint64 nSize, OpenMode mode);

private:
    quint64 adjustSize(quint64 nSize);
#ifdef Q_OS_WIN
    void checkWindowsLastError();
#endif

protected:
    virtual qint64 readData(char *pData, qint64 nMaxSize);
    virtual qint64 writeData(const char *pData, qint64 nMaxSize);
    virtual void setErrorString(const QString &str);

private:
    const qint64 N_BUFFER_SIZE = 0x1000;
    qint64 g_nPID;
    void *g_hProcess;
    quint64 g_nAddress;
    quint64 g_nSize;
};

#endif  // XPROCESSDEVICE_H
