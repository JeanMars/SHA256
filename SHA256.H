#ifndef __SHA256_H
#define __SHA256_H

/*#if defined(__PUREC__)*/
typedef unsigned long uint32_t ;
typedef unsigned char uint8_t ;
/*#else
#include <stdint.h>
#endif*/

/* Compute SHA256 from a file contents:                              */
/* Returns:  0: Success, SHA256 is filled in sha256 array (32 bytes) */
/*          -1: Error, file can't be opened                          */
long fSHA256(const char* name, uint32_t sha256[8]) ;

/* Compute SHA256 from memory:                           */
/* Returns:  SHA256 is filled in sha256 array (32 bytes) */
void mSHA256(void* data, uint32_t size, uint32_t sha256[8]) ;

#endif
