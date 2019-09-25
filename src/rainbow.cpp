
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <stdint.h>
#include <b64/encode.h>
#include <b64/decode.h>
#include "utils.h"
#include <string>
#include <functional>
#include <tuple>
#include <memory.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include "rainbow.h"

using namespace std;

bool md5(const uint8_t* message, size_t len, uint8_t (&hash)[16])
{
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
        return false;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))
        return false;

    if (1 != EVP_DigestUpdate(mdctx, message, len))
        return false;
    uint32_t hashLen = 16;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLen))
        return false;

    EVP_MD_CTX_destroy(mdctx);
}

inline bool cmpKey(const char* endpoint,const char* key)
{
    return *((uint64_t*)(void*)endpoint) == *((uint64_t*)(void*)key);
}

tuple<string, string> generateRainbowChain(uint64_t iteration, function<void(float)> progress)
{
    uint8_t hash[16];
    char key[16];
    base64::encoder b64;
    char target[] = "password";

    memset(key, 0, 16);
    memset(hash, 0, 16);

    getrandom(hash, 16, 0);
    b64.encode((char*)hash, 6, key);
    string startpoint = string(key);

    for (uint64_t i = 0; i < iteration; i++)
    {
        if(progress)
            progress((float)i / iteration);
        
        // hash
        md5((uint8_t*)key, 6, hash);
        // reduction
        b64.encode((char*)hash, 6, key);

        if(cmpKey(startpoint.c_str(), key))
        {
            cerr << "Looped with startup '" << startpoint << "' at length " << i << endl;
        }
        if(cmpKey(target, key))
        {
            cout << "hit" << endl;
        }
    }
    key[8] = 0;
    return make_tuple(startpoint, string(key));
}

mutex m;

void generateProcess(uint64_t length, vector<RainbowChain>* table)
{
    auto [start, end] = generateRainbowChain(length);
    RainbowChain chain;
    chain.entry = start;
    chain.endpoint = end;
    m.lock();
    table->push_back(chain);
    m.unlock();
}

vector<RainbowChain> generateRainbowTable(uint64_t length, size_t count)
{
    const int useThreads = 8;
    vector<RainbowChain> table;
    vector<thread> threads;
    for (size_t k = 0;k < count ;)
    {
        threads.clear();
        for (int i = 0; i < useThreads; i++)
        {
            k++;
            if (k > count)
                break;
            threads.push_back(thread(generateProcess, length, &table));
        }
        for (auto& p : threads)
        {
            p.join();
        }
    }
    return table;
}

string getRainbowEntry(uint8_t* targetHash, vector<RainbowChain>& table, uint64_t maxLength)
{
    uint8_t hash[16];
    char key[16];
    base64::encoder b64;
    memcpy(hash, targetHash, 16);
    b64.encode((char*)hash, 6, key);

    for (int i = 0; i < maxLength; i++)
    {
        // hash
        md5((uint8_t*)key, 6, hash);
        // reduction
        b64.encode((char*)hash, 6, key);

        for(auto & p : table)
        {
            if(cmpKey(key, p.endpoint.c_str()))
            {
                return p.entry;
            }
        }
    }
    return "";
}

string attack(uint8_t* targetHash, vector<RainbowChain>& table, uint64_t maxLength)
{
    auto entry = getRainbowEntry(targetHash, table, maxLength);
    if(entry == "")
    {
        // srand(time(nullptr));
        // auto idx = rand() % table.size();
        // entry = table[idx].entry;
        return "";
    }

    uint8_t hash[16];
    char key[16];
    base64::encoder b64;
    memcpy(key, entry.c_str(), 9);
    for(uint64_t i = 0;i < maxLength; i++)
    {
        // hash
        md5((uint8_t*)key, 6, hash);

        // if (rand() / (double)RAND_MAX < 1)
        // {
        //     char hashBuf[17];
        //     char buffer[64];
        //     base64::encoder e;
        //     auto len = e.encode((char*)hash, 16, buffer);
        //     len += e.encode_end(buffer + len);
        //     buffer[len] = 0;
        //     key[8] = 0;
        //     cout << key << endl;
        //     cout << string(buffer) << endl;
        //     cout << endl;
        // }

        // compare hash
        if(memcmp(hash, targetHash, 16)==0)
        {
            key[8] = 0;
            return string(key);
        }

        // reduction
        b64.encode((char*)hash, 6, key);
    }
    return "";
}