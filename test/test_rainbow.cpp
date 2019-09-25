#include <iostream>
#include <rainbow.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <stdio.h>
#include <b64/decode.h>

using namespace std;

#define CHAIN_LEN 1000000

int main(int argc, char** argv)
{
    if(argc < 2)
    {

        timespec startT, endT;
        clock_gettime(CLOCK_MONOTONIC, &startT);

        auto table = generateRainbowTable(CHAIN_LEN, 100);

        clock_gettime(CLOCK_MONOTONIC, &endT);
        double time = endT.tv_sec - startT.tv_sec;
        time += (endT.tv_nsec - startT.tv_nsec) / 1000000000.0;

        cout << table.size() << endl;
        for (auto& p : table)
        {
            cout << p.entry << " " << p.endpoint << endl;
        }
    }
    else
    {
        FILE* fp = fopen(argv[1], "r");
        size_t length;
        RainbowTable table;
        fscanf(fp, "%ld", &length);
        for (size_t i = 0; i < length; i++)
        {
            char entry[32], endpoint[32];
            RainbowChain chain;
            fscanf(fp, "%s %s", entry, endpoint);
            chain.entry = string(entry);
            chain.endpoint = string(endpoint);
            table.push_back(chain);
        }
        string hash;
        uint8_t buffer[32];
        cin >> hash;
        base64::decoder decoder;
        decoder.decode(hash.data(), hash.size(), (char*)buffer);
        auto plaintext = attack(buffer, table, CHAIN_LEN);
        cout << plaintext << endl;
    }


    exit(0);
}