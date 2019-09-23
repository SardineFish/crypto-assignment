#include "rsa.h"
#include <time.h>

int main()
{
    timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    genRSAKey();

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = end.tv_sec - start.tv_sec;
    time += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

    printf("Completed in %lfs\n", time);
    return 0;
}