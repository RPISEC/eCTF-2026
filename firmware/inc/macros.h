#ifndef MACROS_H_
#define MACROS_H_

#define IF(x) {                                 \
    volatile result = x;                        \
    result = x;                                 \
    result = x;                                 \
    if (x) {                                    \
        result = x;                             \
        if (x) {                                \
            result = x;                         \
            if (x) {

#define ENDIF }                                 \
        }                                       \
    }                                           \
}

#endif // MACROS_H_
