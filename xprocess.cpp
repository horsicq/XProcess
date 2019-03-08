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
                PROCESS_INFO record={0};

                record.nID=pe32.th32ProcessID;
                record.nParentID=pe32.th32ParentProcessID;
                record.sName=QString::fromWCharArray(pe32.szExeFile);

                if(record.nID)
                {
                    HANDLE hModule=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,record.nID);

                    if(hModule!=INVALID_HANDLE_VALUE)
                    {
                        MODULEENTRY32 me32;
                        me32.dwSize=sizeof(MODULEENTRY32);

                        if(Module32First(hModule,&me32))
                        {
                            record.nImageAddress=(qint64)me32.modBaseAddr;
                            record.nImageSize=(qint64)me32.modBaseSize;
                            record.sFilePath=QString::fromWCharArray(me32.szExePath);
                        }

                        CloseHandle(hModule);
                    }
                }

                listResult.append(record);
            }
            while(Process32NextW(hProcesses,&pe32));
        }

        CloseHandle(hProcesses);
    }
#endif
#ifdef Q_OS_LINUX
    // TODO
#endif

    return listResult;
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
