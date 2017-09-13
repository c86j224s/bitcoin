// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "chainparams.h"
#include "clientversion.h"
#include "compat.h"
#include "fs.h"
#include "rpc/server.h"
#include "init.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"
#include "utilstrencodings.h"

#include <boost/thread.hpp>

#include <stdio.h>

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

void WaitForShutdown(boost::thread_group* threadGroup)
{
    // 셧다운 요청이 있기까지 대기하다가, 셧다운 명령이 떨어지면 join_all을 통해 모든 thread group들이 끝나기를 기다리는 함수입니다.

    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])
{
    // 로컬 변수로 생성. 프로그램 만들어지고나서 죽을때 까지.. 얘네들은 실제 AppInitMain 들어갈 때 넘겨준다. (안에서 하면 되지 왜??)
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;

    //
    // Parameters
    //
    // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
    // gArgs 는 util.cpp에 정의된 전역 변수임. /로 시작하는 인자와 --로 시작하는 인자를 -로 시작하도록 통일하고, 인자 맵에 넣는 일을 하고 있음.
    gArgs.ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    // 도움말 혹은 버전을 보길 원하면, 헬프 메시지를 출력하고 종료.
    if (gArgs.IsArgSet("-?") || gArgs.IsArgSet("-h") ||  gArgs.IsArgSet("-help") || gArgs.IsArgSet("-version"))
    {
        std::string strUsage = strprintf(_("%s Daemon"), _(PACKAGE_NAME)) + " " + _("version") + " " + FormatFullVersion() + "\n";

        if (gArgs.IsArgSet("-version"))
        {
            strUsage += FormatParagraph(LicenseInfo());
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + strprintf(_("Start %s Daemon"), _(PACKAGE_NAME)) + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try
    {
        // 데이터 디렉토리를 찾는다. false로 넣은 것은, mainnet이나 testnet에 무관하게 찾는다는 의미.
        if (!fs::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", "").c_str());
            return false;
        }
        // bitcoin.conf를 읽는다. 인자를 넣을 때 절대경로로 넣어야만 바로 위에서 지정된 혹은 기본 datadir에서 읽지 않는다. 컨피그 내용은 사실 실행 인자의 모음과 같이 다루어진다. (즉, 인자 전역변수에 추가 혹은 덮어써진다.)
        try
        {
            gArgs.ReadConfigFile(gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME));
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        // 네트워크에 따라 초기 설정 값을 변경한다.
        try {
            SelectParams(ChainNameFromCommandLine());
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // Error out when loose non-argument tokens are encountered on command line
        // 옵션 인자가 아닌 것이 있었을 경우 종료 !
        for (int i = 1; i < argc; i++) {
            if (!IsSwitchChar(argv[i][0])) {
                fprintf(stderr, "Error: Command line contains unexpected token '%s', see bitcoind -h for a list of options.\n", argv[i]);
                exit(EXIT_FAILURE);
            }
        }

        // -server defaults to true for bitcoind but not for the GUI so do this here
        // 기본적으로 서버로 동작.. GUI일 경우에는 얘를 꺼줌..
        gArgs.SoftSetBoolArg("-server", true);
        // Set this early so that parameter interactions go to console
        // 로그 옵션..
        InitLogging();
        // 의도와 달리 잘못 설정할 수 있는, 사용자의 인자 입력을 고쳐줌.
        InitParameterInteraction();
        // OS, 네트워크 환경 별 기본적인 초기화와 크랙을 막는(DEP 등) 방어코드, 시그널 핸들러 처리 추가 등.
        if (!AppInitBasicSetup())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }
        // TODO -------------------------------------- 여기서부터 이어서....
        if (!AppInitParameterInteraction())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }
        if (!AppInitSanityChecks())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }
        // TODO -------------------------------------- 여기까지 보고 넘어가야 함...
        // 데몬으로 실행해달라고 했으면 데몬으로 실행.
        if (gArgs.GetBoolArg("-daemon", false))
        {
#if HAVE_DECL_DAEMON
            fprintf(stdout, "Bitcoin server starting\n");

            // Daemonize
            // 요건 리눅스 API인듯... 유닉스 표준인지는 잘 모르겠음... 나중에 보자.
            if (daemon(1, 0)) { // don't chdir (1), do close FDs (0)
                fprintf(stderr, "Error: daemon() failed: %s\n", strerror(errno));
                return false;
            }
#else
            fprintf(stderr, "Error: -daemon is not supported on this operating system\n");
            return false;
#endif // HAVE_DECL_DAEMON
        }
        // Lock data directory after daemonization
        // 데몬으로 전환한 다음에도 락이 잘 잡히는지 체크함.
        if (!AppInitLockDataDirectory())
        {
            // If locking the data directory failed, exit immediately
            exit(EXIT_FAILURE);
        }
        // TODO 여기서부터 다시 이어서....................................................................
        fRet = AppInitMain(threadGroup, scheduler);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInit()");
    }

    if (!fRet)
    {
        Interrupt(threadGroup);
        threadGroup.join_all();
    } else {
        WaitForShutdown(&threadGroup);
    }
    Shutdown();

    return fRet;
}

int main(int argc, char* argv[])
{
    // 메인 함수 !!
 
    // C & linux 환경 대응 메모리 및 로케일 설정.
    SetupEnvironment();

    // UI로 보여줄 메시지 박스 시그널 핸들러를 연결. (default는 noui임.)
    // Connect bitcoind signal handlers
    noui_connect();

    // 실제 시작.
    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}
