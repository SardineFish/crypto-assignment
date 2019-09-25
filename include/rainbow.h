#pragma once
#include <string>
#include <tuple>
#include <functional>
#include <vector>

using namespace std;

struct RainbowChain
{
    string entry;
    string endpoint;
};

typedef vector<RainbowChain> RainbowTable;

tuple<string, string> generateRainbowChain(uint64_t iteration, function<void(float)> progress = nullptr);
vector<RainbowChain> generateRainbowTable(uint64_t length, size_t count);
string attack(uint8_t* targetHash, vector<RainbowChain>& table, uint64_t maxLength);