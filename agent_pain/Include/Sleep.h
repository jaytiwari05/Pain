#ifndef SLEEP_H
#define SLEEP_H

#include <windows.h>

// Sleep technique IDs - used with PAIN_SLEEP_TECH compile flag
#define SLEEP_TIMER_SPOOF  0
#define SLEEP_EKKO_GRAFT   1
#define SLEEP_EKKO         2

void Sleep_TimerSpoof( ULONG ms );
void Sleep_EkkoGraft ( ULONG ms );
void Sleep_Ekko      ( ULONG ms );

#endif // SLEEP_H
