/* SHA256 test & file computation */

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.h"

#define ARRAY_SIZE(v)  sizeof(v)/sizeof((v)[0])

typedef struct _SHA256_TEST_VECTOR
{
  char*  string ;
  uint32_t sha256[8] ;
}
SHA256_TEST_VECTOR, *PSHA256_TEST_VECTOR ;


static SHA256_TEST_VECTOR sha256_test_vectors[] =
{
  { "",    { 0xe3b0c442UL, 0x98fc1c14UL, 0x9afbf4c8UL, 0x996fb924UL, 0x27ae41e4UL, 0x649b934cUL, 0xa495991bUL, 0x7852b855UL } },
  { "abc", { 0xba7816bfUL, 0x8f01cfeaUL, 0x414140deUL, 0x5dae2223UL, 0xb00361a3UL, 0x96177a9cUL, 0xb410ff61UL, 0xf20015adUL } },
  { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", { 0x248d6a61UL, 0xd20638b8UL, 0xe5c02693UL, 0x0c3e6039UL, 0xa33ce459UL, 0x64ff2167UL, 0xf6ecedd4UL, 0x19db06c1UL } },
  { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", { 0xcf5b16a7UL, 0x78af8380UL, 0x036ce59eUL, 0x7b049237UL, 0x0b249b11UL, 0xe8f07a51UL, 0xafac4503UL, 0x7afee9d1UL } }
} ;

int main(int argc, char** argv)
{
  uint32_t  sha256[8] ;
  uint32_t  size ;
  clock_t t0, t1 ;
  long    r ;
  int     n ;

  if ( (argc == 1) || ((argc >= 2) && (strcmp( argv[1], "-t" ) == 0)) )
  {
    uint32_t* rsha256 ;
    char*   string ;
    int     nOK = 0 ;

    printf("Test mode:\n") ;
    for ( n = 0; n < ARRAY_SIZE(sha256_test_vectors); n++ )
    {
      size    = strlen(sha256_test_vectors[n].string) ;
      string  =  sha256_test_vectors[n].string ;
      rsha256 = sha256_test_vectors[n].sha256 ;
      mSHA256( string, size, sha256 ) ;
      printf( "SHA256(%s)=%08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx...", string, sha256[0], sha256[1], sha256[2], sha256[3], sha256[4], sha256[5], sha256[6], sha256[7] ) ;
      if ( memcmp(sha256, rsha256, 32) == 0 ) { printf("OK \n") ; nOK++; }
      else                                    printf("FAILED; expecting %08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx\n", rsha256[0], rsha256[1], rsha256[2], rsha256[3], rsha256[4], rsha256[5], rsha256[6], rsha256[7] ) ;
    }
    if ( nOK == n ) printf("All test vectors OK\n") ;
    else            printf("%d test vectors OK, %d FAILED\n", nOK, n-nOK) ;
    printf("Perfomance tests:\n") ;
    size = 1024L ;
    do
    {
      string = malloc( size+64 ) ;
      if ( string )
      {
        t0 = clock() ;
        mSHA256( string, size, sha256 ) ;
        t1 = clock() ;
        free( string ) ;
        if ( t1 != t0 )
        {
          long dt_ms      = (long) ((1000L*(t1-t0))/CLK_TCK) ;
          long kb_per_sec = (long) ((1000L*(size >> 10))/dt_ms) ;

          printf("SHA256 on %ldKB took %ldms (%ldKB/s)\n", size>>10, dt_ms, kb_per_sec) ;
        }
      }
      size <<= 1 ;
    }
    while( (t1-t0 < 2L*CLK_TCK) && string ) ; /* Stop when a SHA256 lasts for at least 2s or no memory left */
  }
  else
  {
    for ( n = 1; n < argc; n++ )
    {
      r = fSHA256( argv[n], sha256 ) ;
      if ( r == 0 ) printf( "SHA256(file:%s)=%08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx\n", argv[n], sha256[0], sha256[1], sha256[2], sha256[3], sha256[4], sha256[5], sha256[6], sha256[7] ) ;
      else          printf( "SHA256(file:%s): error %ld", argv[n], r ) ;
    }
  }

  return 0 ;
}
