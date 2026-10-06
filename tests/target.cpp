#include <windows.h>
extern "C" __declspec(dllimport) int fixture_value();
int main() { return fixture_value()==42 && GetCurrentProcessId()!=0 ? 0 : 1; }
