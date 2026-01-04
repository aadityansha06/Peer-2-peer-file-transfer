#ifndef PROGRESSBAR_H
#define PROGRESSBAR_H

#include <stdio.h>
#include <stdint.h>

#define PROGRESSBAR_WIDTH 50

/**
 * Displays a progress bar in the format [------>    ]
 */
static inline void progressbar(uint64_t current, uint64_t total) {
    if (total == 0) return;

    double percentage = (double)current / total;
    int filled = (int)(percentage * PROGRESSBAR_WIDTH);

    printf("\r[");
    for (int i = 0; i < PROGRESSBAR_WIDTH; i++) {
        if (i < filled) {
            printf("-");
        } else if (i == filled) {
            printf(">");
        } else {
            printf(" ");
        }
    }
    printf("] %3.0f%%", percentage * 100);
    fflush(stdout);
}

#endif
