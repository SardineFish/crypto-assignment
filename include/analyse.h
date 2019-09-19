#pragma once
#include <array>
#include <functional>

using namespace std;

typedef function<tuple<uint16_t, uint16_t>()> PlainCipherGenerator;

typedef function<uint16_t(function<tuple<uint16_t, uint16_t>()>)> subkeyAnalyser;

array<array<int, 16>, 16> genApproximationTable();

uint16_t linearSubkeyAnalyse(function<tuple<uint16_t, uint16_t>()> plaintextGenerator);

uint32_t extractKey(subkeyAnalyser analyser, function<tuple<uint16_t, uint16_t>()> plaintextGenerator);

uint32_t linearCryptanalyse(function<tuple<uint16_t, uint16_t>()> plaintextGenerator);

uint32_t diffCryptanalyse(function<tuple<uint16_t, uint16_t>(uint16_t inputDelta)> plainCipherGenerator);

uint32_t diffCryptanalyse(function<tuple<uint16_t, uint16_t>(uint16_t inputDelta)> deltaGroupGenerator, PlainCipherGenerator plainCipherGenerator);

struct PlainCipherPair
{
    uint16_t plaintext;
    uint16_t cipher;
};