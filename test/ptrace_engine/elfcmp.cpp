#include "ptraceelf.h"
#include <cstdio>
#include <set>
#include <tuple>
using namespace BinaryNinjaDebugger;
int main(int c, char** v){ ElfInfo i; if (!ReadElfFile(v[1], i)) { printf("read failed\n"); return 1; }
 std::set<std::tuple<std::string, unsigned long long, unsigned long long, int>> s; for (auto& x : i.symbols) s.insert({x.name, (unsigned long long)x.address, (unsigned long long)x.size, (int)x.isFunction});
 for (auto& t : s) printf("%s %llx %llu %d\n", std::get<0>(t).c_str(), std::get<1>(t), std::get<2>(t), std::get<3>(t)); }
