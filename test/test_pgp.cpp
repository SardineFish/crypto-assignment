#include "pgp.h"
#include <stdlib.h>
#include <iostream>

int main()
{
    cout << hex << 236 << endl;
    cout.flush();
    string key = "password";
    string plaintext = "Hello World!\n";
    char buffer[8192];
    size_t length;
    array<uint8_t, 32> buf256;

    sha256(key.c_str(), key.size(), buf256);
    cout << hex(buf256.data(), buf256.size()) << endl;
    return 0;
}