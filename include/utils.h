#pragma once
#include <sys/syscall.h>
#include <unistd.h>
#define getrandom(buf, len, flag) syscall(SYS_getrandom, buf, len, flag);