#include "fileio.h"

#include <stdlib.h>


void *read_file(FILE *fp, const size_t len) {
    void *data = malloc(len);
    if (fread(data, len, 1, fp) != 1) {
        free(data);
        perror("read_file");
        return NULL;
    }
    return data;
}


void *read_file_off(FILE *fp, const size_t len, const long int offset) {
    fseek(fp, offset, SEEK_SET);
    return read_file(fp, len);
}
