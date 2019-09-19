#include "spn.h"
#include "analyse.h"
#include <array>
#include <memory.h>
#include <vector>

using namespace std;

array<array<int, 16>, 16> DifferenceDistributionTable;
void generateDifferenceDistributionTable()
{
    for (int i = 0; i < 16;i++)
    {
        for (int j = 0; j < 16;j++)
            DifferenceDistributionTable[i][j] = 0;
    }
    for (int deltaX = 0; deltaX < 16; deltaX++)
    {
        for (int x = 0; x < 16; x++)
        {
            int anotherX = deltaX ^ x;
            int y = fastSBox(x);
            int anotherY = fastSBox(anotherX);
            int deltaY = y ^ anotherY;
            DifferenceDistributionTable[deltaX][deltaY]++;
        }
    }

    // for (int i = 0; i < 16; i++)
    // {
    //     for (int j = 0; j < 16; j++)
    //         printf("%2d, ", DifferenceDistributionTable[i][j]);
    //     printf("\n");
    // }
}

inline int findMaxDifferenceOutput(int inputDelta)
{
    int maxCount = 0;
    int output = 0;
    for (int outputDelta = 0; outputDelta < 16; outputDelta++)
    {
        if (DifferenceDistributionTable[inputDelta][outputDelta] > maxCount)
        {
            output = outputDelta;
            maxCount = DifferenceDistributionTable[inputDelta][outputDelta];
        }
    }
    return output;
}

tuple<uint16_t, double> findDifferenceCharacteristic(uint16_t entry)
{
    uint16_t roundIn = entry;
    double prob = 1;
    for (int round = 0; round < 3; round++)
    {
        uint16_t roundOut = 0;
        for (int i = 0; i < 4;i++)
        {
            if(int boxIn = get_box(roundIn, i))
            {
                auto boxOut = findMaxDifferenceOutput(boxIn);
                prob *= DifferenceDistributionTable[boxIn][boxOut] / 16.0;
                roundOut |= set_box(boxOut, i);
            }
        }
        roundOut = fastPermutate(roundOut);
        roundIn = roundOut;
    }
    return make_tuple(roundIn, prob);
}

uint16_t differenceSubkeyAnalyse(function<tuple<uint16_t, uint16_t>(uint16_t inputDelta)> plainCipherGenerator)
{
    generateDifferenceDistributionTable();
    const uint16_t entry = 0b0000101100000000;
    // with output 0b0000011000000110
    const auto [roundOut, expectProb] = findDifferenceCharacteristic(entry);
    // for (int i = 0; i < 0x10000;i++)
    // {
    //     uint16_t in = i;
    //     auto [out, prob] = findDifferenceCharacteristic(in);
    //     if(prob > 0.02)
    //     {
    //         printf("%016lld: %016lld, %lf\n", stob(in), stob(out), prob);
    //     }
    // }

    int count[0x100];
    memset(count, 0, sizeof(count));

    const int enumTimes = 5000;
    for (int i = 0; i < enumTimes; i++)
    {
    SkipWrongPair:
        const auto [y1, y2] = plainCipherGenerator(entry);
        auto outputDelta = y1 ^ y2;
        if (get_box(outputDelta, 1) != 0 || get_box(outputDelta, 3) != 0)
            goto SkipWrongPair;
        for (int enumKey = 0; enumKey < 0x100; enumKey++)
        {
            uint16_t key = set_box(get_box(enumKey, 0), 0) | set_box(get_box(enumKey, 1), 2);
            uint16_t lastRoundA = fastReverseSubstitute((key ^ y1));
            uint16_t lastRoundB = fastReverseSubstitute((key ^ y2));
            uint16_t lastRoundDelta = lastRoundA ^ lastRoundB;
            if (lastRoundDelta == roundOut)
                count[enumKey]++;
        }
    }

    int maxCounter = 0;
    int targetKey = 0;
    for (int enumKey = 0; enumKey < 0x100; enumKey++)
    {
        if(count[enumKey] > maxCounter)
        {
            maxCounter = count[enumKey];
            targetKey = enumKey;
        }
    }
    return set_box(get_box(targetKey, 0), 0) | set_box(get_box(targetKey, 1), 2);
}

uint32_t diffCryptanalyse(function<tuple<uint16_t, uint16_t>(uint16_t inputDelta)> deltaGroupGenerator, PlainCipherGenerator plainCipherGenerator)
{
    uint16_t subkey = differenceSubkeyAnalyse(deltaGroupGenerator);

    vector<PlainCipherPair> pairs;
    for (int i = 0; i < 16; i++)
    {
        const auto [plaintext, cipher] = plainCipherGenerator();
        pairs.push_back({plaintext, cipher});
    }

    for (uint64_t i = 0; i < 0x1000000; i++)
    {
        uint32_t key = (subkey << 16) | ((i & 0xF0000) << 4) | ((i & 0xF00000) << 8) | (i & 0xFFFF);
        // if((i & 0xFFFF) == 0)
        // {
        //     printf("%016lld\n", stob(key >> 16));
        // }
        for (auto &p : pairs)
        {
            if (encryptSPN(p.plaintext, key) != p.cipher)
                goto WrongKey;
        }
        return key;
    WrongKey:
        int x = 0;
    }
    return 0;
}