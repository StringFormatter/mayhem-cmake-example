#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fuzzme(char *buf)
{
  if(strlen(buf) >= 3)
    if(buf[0] == 'b')
      if(buf[1] == 'u')
        if(buf[2] == 'g') {
          printf("You've got it!");
          abort();
        }
    return 0;
}

#define BUFSZ 256

int LLVMFuzzerTestOneInput(char* data, size_t size)
{
    size_t bufsz = size < BUFSZ ? size : BUFSZ;
    data[bufsz] = 0 ;
    FILE* f = NULL;
    size_t nr = 0;

    f = fopen(data, "rb");
    assert(f);

    nr = fread(data, sizeof(data[0]), bufsz, f);
    assert(nr > 0);
    data[bufsz-1] = '\0';

    fuzzme(data);

    fclose(f);

    return 0;
}

