/**
 * @file fileio.h
 * @brief Utility functions for reading binary data from files into memory.
 */

#ifndef FILEIO_H
#define FILEIO_H

#include <stdio.h>

/**
 * @brief Reads a specified number of bytes from the current position in a file.
 *
 * Allocates a memory buffer of size `len` and reads `len` bytes from the given
 * file stream. The caller is responsible for freeing the allocated memory.
 *
 * @param fp  Pointer to an open file stream (FILE*).
 * @param len Number of bytes to read and allocate.
 *
 * @return Pointer to the allocated buffer containing the read data, 
 *         or NULL if memory allocation fails or the read operation fails.
 *
 * @note If an error occurs during reading, allocated memory is freed 
 *       and an error message is printed to stderr via perror().
 */
void *read_file(FILE *fp, const size_t len);

/**
 * @brief Reads a specified number of bytes from a given offset in a file.
 *
 * Repositions the file position indicator to `offset` relative to the beginning
 * of the file (SEEK_SET), then reads `len` bytes into a dynamically allocated buffer.
 *
 * @param fp     Pointer to an open file stream (FILE*).
 * @param len    Number of bytes to read and allocate.
 * @param offset Byte offset from the start of the file where reading begins.
 *
 * @return Pointer to the allocated buffer containing the read data,
 *         or NULL if seek/read operations fail or memory allocation fails.
 *
 * @note The caller is responsible for freeing the returned pointer.
 */
void *read_file_off(FILE *fp, const size_t len, const long int offset);

#endif /* FILEIO_H */