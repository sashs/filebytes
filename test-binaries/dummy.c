// clang -o dummy.x86_64 -m64 dummy.c -isysroot /path/to/MacOSX10.10.sdk
// clang -o dummy.x86 -m32 dummy.c -isysroot /path/to/MacOSX10.10.sdk
// lipo -create dummy.x86_64 dummy.x86 -output dummy-macho-universal-x86-x86_64

#include <stdio.h>

int main() {
  printf("hello world\n");
}
