#include "analyse.h"
#include "spn.h"
#include <tuple>
#include <stdlib.h>
#include <iostream>
#include <time.h>

using namespace std;

int main()
{
    timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    srand(time(nullptr));
    auto table = genApproximationTable();
    const uint32_t key = 0b00111010100101001101011000111111;
    // const uint16_t lastkey = extractSubKey([]() -> tuple<uint16_t, uint16_t> {
    //     const uint16_t plaintext = (uint16_t)rand();
    //     const uint16_t cipher = encryptSPN(plaintext, key);
    //     return make_tuple(plaintext, cipher);
    // });
    const uint32_t calcKey = extractKey([]() -> tuple<uint16_t, uint16_t> {
        const uint16_t plaintext = (uint16_t)rand();
        const uint16_t cipher = encryptSPN(plaintext, key);
        return make_tuple(plaintext, cipher);
    });

    printf("%016lld\n", stob(calcKey & 0xFFFFF));
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = end.tv_sec - start.tv_sec;
    time += (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    if (calcKey == key)
        cout << "Key correct." << endl;
    else if(calcKey >> 20 == key >> 20)
        cout << "Wrong key with correct subkey." << endl;
    else
        cout << "Wrong key with wrong subkey." << endl;
    printf("Completed in %lfs.\n", time);
    return 0;
}