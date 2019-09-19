#pragma once
#include <array>
#include <functional>

using namespace std;

array<array<int, 16>, 16> genApproximationTable();

uint16_t extractSubKey(function<tuple<uint16_t, uint16_t>()> plaintextGenerator);

uint32_t extractKey(function<tuple<uint16_t, uint16_t>()> plaintextGenerator);