#include "analyse.h"
#include "spn.h"
#include "bits.h"
#include <array>
#include <vector>
#include <tuple>
#include <functional>
#include <cmath>
#include <stdio.h>
#include <sys/random.h>
#include <memory.h>
#include <thread>

using namespace std;

array<array<int, 16>, 16> ApproximationTable;

array<array<int, 16>, 16> genApproximationTable()
{
    auto table = array<array<int, 16>, 16>();
    for (auto i = 0; i < 16; i++)
    {
        table[i] = array<int, 16>();
    }
    for (int inputMask = 0; inputMask < 16; inputMask++)
    {

        for (int outputMask = 0; outputMask < 16; outputMask++)
        {
            for (int x = 0; x < 16; x++)
            {
                int y = substituteBox(x);
                int result = 0;
                int mx = inputMask & x;
                int my = outputMask & y;
                result ^= xor_bits(mx) ^ xor_bits(my);
                if (result == 0)
                    table[inputMask][outputMask]++;
            }
            table[inputMask][outputMask] -= 8;
            // printf("%2d, ", table[inputMask][outputMask]);
        }
        // printf("\n");
    }
    ApproximationTable = table;
    return table;
}

inline int findMaxBiasApproximation(int input)
{
    int maxBias = 0;
    int output = 0;
    for (int i = 0; i < 16; i++)
    {
        if (abs(ApproximationTable[input][i]) > maxBias)
        {
            output = i;
            maxBias = abs(ApproximationTable[input][i]);
        }
    }
    return output;
}

tuple<uint16_t, double> findLinearApproximation(uint16_t entry)
{
    uint16_t roundIn = entry;
    double bias = 1;
    int biasCount = 0;
    for (int i = 0; i < 3; i++)
    {
        uint16_t roundOut = 0;
        for (int i = 0; i < 4; i++)
        {
            if (int boxIn = get_box(roundIn, i))
            {
                auto boxOut = findMaxBiasApproximation(boxIn);
                bias *= (double)ApproximationTable[boxIn][boxOut] / 16.0;
                biasCount++;
                roundOut |= set_box(boxOut, i);
            }
        }
        roundOut = permutate(roundOut);
        roundIn = roundOut;
    }
    bias *= pow(2, biasCount - 1);
    return make_tuple(roundIn, bias);
}

void calculateBias(int* count, int enumTimes, uint16_t inMask, uint16_t outMask, function<tuple<uint16_t, uint16_t>()> plaintextGenerator)
{
    for (int i = 0; i < enumTimes;i++)
    {
        const auto [plaintext, cipher] = plaintextGenerator();
        for (int enumKey = 0; enumKey < 0x1000; enumKey++)
        {
            // uint16_t key = 0;
            // for (int j = 0; j < boxesCount; j++)
            // {
            //     key |= set_box(get_box(enumKey, j), boxes[j]);
            // }
            uint16_t key = enumKey << 4;
            uint16_t lastRound = key ^ cipher;
            lastRound = fastReverseSubstitute(lastRound);
            lastRound = lastRound & outMask;
            int sum = xor_bits_16(inMask & plaintext) ^ xor_bits_16(lastRound);
            if (sum == 0)
                count[enumKey]++;
        }
    }
}

uint16_t extractSubKey(function<tuple<uint16_t, uint16_t>()> plaintextGenerator)
{
    const uint16_t entry = 0b0000000011001100;
    const auto [roundOut, expectBias] = findLinearApproximation(entry);
    // for (int i = 0; i < 0x10000; i++)
    // {
    //     uint16_t in = i;
    //     getrandom(&in, sizeof(uint16_t), 0);
    //     auto [out, bias] = findLinearApproximation(in);
    //     //printf("%016lld: %016lld, %lf\n", stob(in), stob(out), bias);
    //     if(abs(bias) > 0.050)
    //     {
    //         printf("%016lld: %016lld, %lf\n", stob(in), stob(out), bias);
    //     }
    // }
    vector<int> boxes;
    int keyCount = 1;
    for (int i = 0; i < 4; i++)
    {
        if (get_box(roundOut, i))
        {
            boxes.push_back(i);
            keyCount = keyCount << 4;
        }
    }
    int boxesCount = boxes.size();
    int count[0x10000];
    const int enumTimes = 1000;
    //(int)pow(1.0 / (double)expectBias, 2);
    memset(count, 0, sizeof(count));
    vector<thread> threads;
    const int ThreadsCount = 8;
    for (int i = 0; i < ThreadsCount; i++)
    {
        threads.push_back(thread(calculateBias, count, enumTimes, entry, roundOut, plaintextGenerator));
    }
    for(auto &p : threads)
    {
        p.join();
    }
    // for (int i = 0; i < enumTimes; i++)
    // {
    //     printf("%f%%\n", i * 100.0f / enumTimes);
    //     const auto [plaintext, cipher] = plaintextGenerator();
    //     for (int enumKey = 0; enumKey < 0x10000; enumKey++)
    //     {
    //         // uint16_t key = 0;
    //         // for (int j = 0; j < boxesCount; j++)
    //         // {
    //         //     key |= set_box(get_box(enumKey, j), boxes[j]);
    //         // }
    //         uint16_t lastRound = enumKey ^ cipher;
    //         lastRound = fastReverseSubstitute(lastRound);
    //         lastRound = lastRound & roundOut;
    //         int sum = xor_bits_16(entry & plaintext) ^ xor_bits_16(lastRound);
    //         if (sum == 0)
    //             count[enumKey]++;
    //     }
    //     }
    double minBias = 1;
    double maxBias = 0;
    uint16_t resultKeyID = 0;
    double resultBias = 0;
    for (int i = 0; i < keyCount; i++)
    {
        auto bias = (double)count[i] / (double)(enumTimes * ThreadsCount) - 0.5;
        if(abs(bias) > abs(maxBias))
            maxBias = bias;
        if (abs(abs(bias) - abs(expectBias)) < minBias)
        {
            minBias = abs(abs(bias) - abs(expectBias));
            resultBias = bias;
            resultKeyID = i;
        }
    }
    printf("%016lld\n", stob(resultKeyID << 4));
    return resultKeyID << 4;
    uint16_t resultKey = 0;
    for (int j = 0; j < boxesCount; j++)
    {
        resultKey |= set_box(get_box(resultKeyID, j), boxes[j]);
    }
    return resultKey;
}

struct PlainCipherPair
{
    uint16_t plaintext;
    uint16_t cipher;
};

uint32_t extractKey(function<tuple<uint16_t, uint16_t>()> plaintextGenerator)
{
    uint32_t keyHigh = extractSubKey(plaintextGenerator) << 16;

    vector<PlainCipherPair> pairs;
    for (int i = 0; i < 3;i++)
    {
        const auto [plaintext, cipher] = plaintextGenerator();
        pairs.push_back({plaintext, cipher});
    }

    for (int i = 0; i < 0x100000; i++)
    {
        uint32_t key = keyHigh | i;
        for(auto & p : pairs)
        {
            if(encryptSPN(p.plaintext, key)!=p.cipher)
                goto WrongKey;
        }
        return key;
    WrongKey:
        int x = 0;
    }
    return 0;
}