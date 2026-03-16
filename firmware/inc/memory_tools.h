#ifndef __MEMORY_TOOLS_H__
#define __MEMORY_TOOLS_H__

#include <stdbool.h>

void init_stack_guard(void);
bool stack_overflow_detected(void);

#endif // __MEMORY_TOOLS_H__
