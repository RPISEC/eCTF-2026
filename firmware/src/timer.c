/**
 * @file timer.c
 * @author Jeremy Goldberger
 * @brief Simple timer API
 * @date 2026
 */

#include "ti_msp_dl_config.h"

// from ti_msp_dl_config.h
#define TIMER_CLOCK_FREQ 125000

volatile uint32_t timer_overflows = 0;

void reset_timer() {
    DL_Timer_stopCounter(TIMER_0_INST);
    
    DL_Timer_setTimerCount(TIMER_0_INST, TIMER_0_INST_LOAD_VALUE);
    timer_overflows = 0;
    
    DL_Timer_startCounter(TIMER_0_INST);
}

bool init_timer() {
    NVIC_EnableIRQ(TIMER_0_INST_INT_IRQN);
    return true;
}

float get_timer_ms() {
    uint32_t overflows;
    uint32_t current_count;
    do {
        overflows = timer_overflows;
        current_count =  DL_Timer_getTimerCount(TIMER_0_INST);
    } while (overflows != timer_overflows);

    uint64_t total_ticks = (uint64_t)overflows * (TIMER_0_INST_LOAD_VALUE + 1);
    total_ticks += (TIMER_0_INST_LOAD_VALUE - current_count);

    return (float)total_ticks / (TIMER_CLOCK_FREQ / 1000.0f);
}

void TIMER_0_INST_IRQHandler(void) {
    if (DL_Timer_getPendingInterrupt(TIMER_0_INST) == DL_TIMERG_IIDX_ZERO) {
        timer_overflows++;
    }
}