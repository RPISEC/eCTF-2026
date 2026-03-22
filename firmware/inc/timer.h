#ifndef __TIMER_H__
#define __TIMER_H__

#include <stdbool.h>
#include <stdint.h>

void reset_timer(void);
uint64_t get_timer_ms(void);
bool init_timer(void);
void print_time(void);

#endif // __TIMER_H__
