#ifndef MACROS_H_
#define MACROS_H_

#include <stdint.h>
#include <simple_trng.h>

#define CONCAT_INNER(x, y) x ## y
#define CONCAT(x, y) CONCAT_INNER(x, y)


/**
 * @brief Check a conditional multiple times. Use in critical if statements
 *        so jumps cannot be skipped by voltage fault injection
 */
#define IF(x) {                                 \
    volatile uint8_t CONCAT(result, __LINE__) = x;      \
    CONCAT(result, __LINE__) = x;               \
    CONCAT(result, __LINE__) = x;               \
    if (CONCAT(result, __LINE__)) {             \
        CONCAT(result, __LINE__) = x;           \
        if (CONCAT(result, __LINE__)) {         \
            CONCAT(result, __LINE__) = x;       \
            if (CONCAT(result, __LINE__)) {     \

#define ENDIF }                                 \
        }                                       \
    }                                           \
}

/**
 * @brief Wait for a random amount of time. Use before critical sections to
 *        disrupt timing attacks, such as voltage fault injection.
 */
#define JITTER do {                                                     \
        volatile uint32_t CONCAT(val, __LINE__) = trng_get_u32() % 42;  \
        for (uint32_t CONCAT(i, __LINE__) = 0; CONCAT(i, __LINE__) < CONCAT(val, __LINE__); CONCAT(i, __LINE__)++, CONCAT(val, __LINE__) = trng_get_u32() % 42) { \
            volatile uint32_t CONCAT(a, __LINE__) = 1630895 * CONCAT(i, __LINE__); \
            volatile uint32_t CONCAT(b, __LINE__) = ((CONCAT(a, __LINE__) & 0xFFFF) << 16 ^ (CONCAT(a, __LINE__) & 0xFFFF0000)) | (CONCAT(a, __LINE__) & 0xFFFF0000 >> 16) | (CONCAT(a, __LINE__) & 0xFFFF); \
            goto CONCAT(LABEL3, __LINE__);                              \
        CONCAT(LABEL1, __LINE__):                                       \
            continue;                                                   \
        CONCAT(LABEL2, __LINE__): ;                                     \
            volatile uint32_t CONCAT(c, __LINE__) = CONCAT(a, __LINE__) * CONCAT(b, __LINE__) & CONCAT(val, __LINE__); \
            goto CONCAT(LABEL1, __LINE__);                              \
        CONCAT(LABEL3, __LINE__):                                       \
            CONCAT(a, __LINE__) = CONCAT(val, __LINE__) * CONCAT(c, __LINE__) ^ CONCAT(b, __LINE__); \
            goto CONCAT(LABEL2, __LINE__);                              \
        }                                                               \
    } while(0)

#endif // MACROS_H_
