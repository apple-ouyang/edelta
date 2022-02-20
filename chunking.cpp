

//#include "stdafx.h"

#include <cstring>

#include "openssl/md5.h"
#include "openssl/sha.h"
#include "chunking.h"
#include "parameters.h"


//�뺯��slide8��Ч����ʹ�ú��滻�ٶȸ���
//����rabin����hash�ķ���
#define SLIDE(m, fingerprint, bufPos, buf)                                     \
  do {                                                                         \
    unsigned char om;                                                          \
    uint64_t x;                                                               \
    if (++bufPos >= size) /*size=32 (the window size)*/                        \
      bufPos = 0;                                                              \
    om = buf[bufPos];                                                          \
    buf[bufPos] = m;                                                           \
    fingerprint ^= U[om];                                                      \
    x = fingerprint >> shift;                                                  \
    fingerprint <<= 8;                                                         \
    fingerprint |= m;                                                          \
    fingerprint ^= T[x];                                                       \
  } while (0)

//�뺯��slide8��Ч����ʹ�ú��滻�ٶȸ���
#define SLIDE2(m, fingerprint, bufPos, buf)                                    \
  do {                                                                         \
    unsigned char om;                                                          \
    uint64_t x;                                                               \
    if (++bufPos >= size)                                                      \
      bufPos = 0;                                                              \
    om = buf[bufPos];                                                          \
    buf[bufPos] = m;                                                           \
    fingerprint ^= U[om];                                                      \
    x = fingerprint >> shift;                                                  \
    fingerprint <<= 8;                                                         \
    fingerprint |= m;                                                          \
    fingerprint ^= T[x];                                                       \
  } while (0)

#define INTTOSTRING(Bint, string)                                              \
  do {                                                                         \
    u_int32_t i;                                                               \
    i = 0;                                                                     \
    while (Bint) {                                                             \
      Bint >>= 4;                                                              \
      i++;                                                                     \
    }                                                                          \
  } while (0)

#define DMEANSIZE 512
#define AVRGESIZE 8192

#define GetLastBits(x, s) ((x << (64U - s)) >> (64U - s))
#define GetUperBits(x, s) (x >> s)
#define CombineBits(x, y, s) (x | (y << s))
#define ROL64(x, s) ((x << s) | (x >> (64U - s)))

// time_t backup_now;
int NUMFEATURE = 2;

uint32_t SSize[256]; // identical chunk size
uint32_t DSize[256]; // deduped chunk size
uint32_t CSize[256]; // chunk size = identical chunk size + deduped chunk size
uint32_t Finger[65536];

enum {
  Mask_64B,
  Mask_128B,
  Mask_256B,
  Mask_512B,
  Mask_1KB,
  Mask_2KB,
  Mask_4KB,
  Mask_8KB,
  Mask_16KB,
  Mask_32KB,
  Mask_64KB,
  Mask_128KB
};

uint64_t g_condition_mask[] = {
    0x00001803110,      // 64B
    0x000018035100,     // 128B
    0x00001800035300,   // 256B
    0x000019000353000,  // 512B
    0x0000590003530000, // 1KB
    0x0000d90003530000, // 2KB
    0x0000d90103530000, // 4KB
    0x0000d90303530000, // 8KB
    0x0000d90703530000, // 16KB
    0x0003590703530000, // 32KB
    0x0007590703530000, // 64KB
    0x0007590713530000  // 128KB
};

enum { size = 32 };
uint64_t fingerprint;
int bufpos;
uint64_t U[256];
unsigned char buf[size]; // size=32
int shift;
uint64_t T[256];
uint64_t poly;

size_t _last_pos;
size_t _cur_pos;

unsigned int _num_chunks;

uint32_t rabin_chunk_size = AVRGESIZE - 1; // AVRGESIZE=8192
uint32_t rabin_chunk_sizeA = AVRGESIZE * 4 - 1;
uint32_t rabin_chunk_sizeB = AVRGESIZE / 4 - 1;
uint32_t min_chunk_size = 2048;
uint32_t max_chunk_size = 65536;

// uint32_t max_chunk_size = 65536*10;
// uint32_t min_chunk_size = 2;

static const unsigned chunk_size = 8191; // 32768;//8198
static unsigned min_size_suppress;
static unsigned max_size_suppress;

uint32_t subChunk_sizeA = DMEANSIZE * 4 - 1;
uint32_t subChunk_sizeB = DMEANSIZE / 4 - 1;
uint32_t max_subChunk_size = DMEANSIZE * 3; // DMEANSIZE=512

uint32_t box_chunk_size = AVRGESIZE - 1;
uint32_t box_chunk_sizeA = AVRGESIZE * 4 - 1;
uint32_t box_chunk_sizeB = AVRGESIZE / 4 - 1;

extern uint32_t dDelta_AVG_Size;
extern uint32_t dDelta_MAX_Size;
extern uint32_t dDelta_MIN_Size;

// UCHAR chunk[70000];

const char bytemsb[0x100] = {
    0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
};

/***********************************************the
 * rabin**********************************************/
static uint32_t fls32(uint32_t v) {
  if (v & 0xffff0000) {
    if (v & 0xff000000)
      return 24 + bytemsb[v >> 24];
    else
      return 16 + bytemsb[v >> 16];
  }
  if (v & 0x0000ff00)
    return 8 + bytemsb[v >> 8];
  else
    return bytemsb[v];
}

static uint32_t fls64(uint64_t v) {
  uint32_t h;
  if ((h = v >> 32))
    return 32 + fls32(h);
  else
    return fls32((uint32_t)v);
}

uint64_t polymod(uint64_t nh, uint64_t nl, uint64_t d) {

  int k = fls64(d) - 1;
  int i;

  // printf ("polymod : k = %d\n", k);

  d <<= 63 - k;

  // printf ("polymod : d = %llu\n", d);
  // printf ("polymod : MSB64 = %llu\n", MSB64);

  if (nh) {
    if (nh & MSB64)
      nh ^= d;

    // printf ("polymod : nh = %llu\n", nh);

    for (i = 62; i >= 0; i--)
      if (nh & ((uint64_t)1) << i) {
        nh ^= d >> (63 - i);
        nl ^= d << (i + 1);

        // printf ("polymod : i = %d\n", i);
        // printf ("polymod : shift1 = %llu\n", (d >> (63 - i)));
        // printf ("polymod : shift2 = %llu\n", (d << (i + 1)));
        // printf ("polymod : nh = %llu\n", nh);
        // printf ("polymod : nl = %llu\n", nl);
      }
  }
  for (i = 63; i >= k; i--) {
    if (nl & (long long int)(1) << i)
      nl ^= d >> 63 - i;

    // printf ("polymod : nl = %llu\n", nl);
  }

  // printf ("polymod : returning %llu\n", nl);

  return nl;
}

void polymult(uint64_t *php, uint64_t *plp, uint64_t x, uint64_t y) {

  int i;

  // printf ("polymult (x %llu y %llu)\n", x, y);

  uint64_t ph = 0, pl = 0;
  if (x & 1)
    pl = y;
  for (i = 1; i < 64; i++)
    if (x & ((long long int)(1) << i)) {

      // printf ("polymult : i = %d\n", i);
      // printf ("polymult : ph = %llu\n", ph);
      // printf ("polymult : pl = %llu\n", pl);
      // printf ("polymult : y = %llu\n", y);
      // printf ("polymult : ph ^ y >> (64-i) = %llu\n", (ph ^ y >> (64-i)));
      // printf ("polymult : pl ^ y << i = %llu\n", (pl ^ y << i));

      ph ^= y >> (64 - i);
      pl ^= y << i;

      // printf ("polymult : ph %llu pl %llu\n", ph, pl);
    }
  if (php)
    *php = ph;
  if (plp)
    *plp = pl;

  // printf ("polymult : h %llu l %llu\n", ph, pl);
}

uint64_t append8(uint64_t p, unsigned char m) {
  return ((p << 8) | m) ^ T[p >> shift];
}

uint64_t slide8(unsigned char m) {
  unsigned char om;
  // printf("this char is %c\n",m);
  if (++bufpos >= size)
    bufpos = 0;
  om = buf[bufpos];
  buf[bufpos] = m;
  return fingerprint = append8(fingerprint ^ U[om], m);
}

uint64_t polymmult(uint64_t x, uint64_t y, uint64_t d) {

  // printf ("polymmult (x %llu y %llu d %llu)\n", x, y, d);

  uint64_t h, l;
  polymult(&h, &l, x, y);
  return polymod(h, l, d);
}

void calcT(uint64_t poly) {

  int j;
  uint64_t T1;

  // printf ("rabinpoly::calcT ()\n");

  int xshift = fls64(poly) - 1;
  shift = xshift - 8;
  T1 = polymod(0, (long long int)(1) << xshift, poly);
  for (j = 0; j < 256; j++) {
    T[j] = polymmult(j, T1, poly) | ((uint64_t)j << xshift);

    // printf ("rabinpoly::calcT tmp = %llu\n", polymmult (j, T1, poly));
    // printf ("rabinpoly::calcT shift = %llu\n", ((uint64_t) j << xshift));
    // printf ("rabinpoly::calcT xshift = %d\n", xshift);
    // printf ("rabinpoly::calcT T[%d] = %llu\n", j, T[j]);
  }

  // printf ("rabinpoly::calcT xshift = %d\n", xshift);
  // printf ("rabinpoly::calcT T1 = %llu\n", T1);
  // printf ("rabinpoly::calcT T = {");
  // for (i=0; i< 256; i++)
  // printf ("\t%llu \n", T[i]);
  // printf ("}\n");
}

void rabinpoly_init(uint64_t p) {
  poly = p;
  calcT(poly);
}

void window_init(uint64_t poly) {
  int i;
  uint64_t sizeshift;

  rabinpoly_init(poly);
  fingerprint = 0;
  bufpos = -1;
  sizeshift = 1;
  for (i = 1; i < size; i++)
    sizeshift = append8(sizeshift, 0);
  for (i = 0; i < 256; i++)
    U[i] = polymmult(i, sizeshift, poly);
  memset((char *)buf, 0, sizeof(buf));
}

void windows_reset() {
  fingerprint = 0;
  memset((char *)buf, 0, sizeof(buf)); // buf is an array of 32 unsigned chars
  // memset((char*) chunk,0,sizeof (chunk));
}

uint32_t GEAR[512]; // should be 256..

void BOXCAR_init() {
  char seed[32];
  for (int i = 0; i < 256; i++) {
    for (int j = 0; j < 32; j++) {
      seed[j] = i;
    }
    GEAR[i] = 0;
    {
#if 1
      unsigned char digest[16];
      MD5_CTX ctx;
      MD5_Init(&ctx);
      MD5_Update(&ctx, seed, 32);
      MD5_Final(digest, &ctx);
      memcpy(&GEAR[i], digest, 8);
#else
      unsigned char digest[20];
      SHA_CTX ctx;
      SHA1_Init(&ctx);
      SHA1_Update(&ctx, seed, 32);
      SHA1_Final(digest, &ctx);
      memcpy(&GEAR[i], digest, 7);
#endif
    }
  }
  dDelta_AVG_Size = 64 - 1;
  dDelta_MAX_Size = 256;
  dDelta_MIN_Size = 32;
}

uint32_t SAMPLEBYTE[256];

void samplebyte_init() {
  for (int i = 0; i < 256; ++i) {
    SAMPLEBYTE[i] = 0;
  }
  // SAMPLEBYTE[0]=1;
  // SAMPLEBYTE[32]=1;
  // SAMPLEBYTE[48]=1;
  // SAMPLEBYTE[101]=1;
  // SAMPLEBYTE[105]=1;
  // SAMPLEBYTE[115]=1;
  SAMPLEBYTE[116] = 1;
  // SAMPLEBYTE[255]=1;
}

void chunkAlg_init_edelta() {
  window_init(FINGERPRINT_PT);
  _last_pos = 0;
  _cur_pos = 0;
  windows_reset();
  _num_chunks = 0;
  BOXCAR_init();
  samplebyte_init();
  // printf("Chunking Init OK!\r\n\r\n %d\n",shift);
}

int Flog2(int input) {
  int output = 0, N = input;
  while (N) {
    N = N / 2;
    output++;
  }
  return output;
}
int chunk_data(unsigned char *p, int n) {

  uint64_t f_break = 0;
  uint64_t count = 0;
  uint64_t fingerprint = 0, w_digest;
  int i = 1, bufPos = -1, stati = 0, minflag = 0;

  unsigned char om;
  uint64_t x;

  unsigned char buf[128];
  memset((char *)buf, 0, 128);

  if (n <= min_chunk_size)
    return n;
  else
    i = min_chunk_size;
  windows_reset();

  for (int j = 48; j >= 2; j--) {
    SLIDE(p[i - j], fingerprint, bufPos, buf);
  }
  while (i < n) {

    SLIDE(p[i - 1], fingerprint, bufPos, buf);
    // Finger[ fingerprint & 16383 ]++;
#if 0
		if( i <=rabin_chunk_size )
		{		    
			w_digest = (fingerprint & rabin_chunk_sizeA); 
		}
		else  
		{
			w_digest = (fingerprint & rabin_chunk_sizeB); 		
		}
		
		if( w_digest==BREAKMARK_VALUE || i >= max_chunk_size || i==n )
			break;
		i++;

#else
    if (((fingerprint & rabin_chunk_size) == BREAKMARK_VALUE) ||
        i >= max_chunk_size) {
      break;
    } else
      i++;
#endif
  }

  return i;
}

int chunk_data_delta(unsigned char *p, int n) {
  uint64_t f_break = 0;
  uint64_t count = 0;
  uint64_t fingerprint = 0, w_digest;
  int i = 1, bufPos = -1, stati = 0, minflag = 0;

  unsigned char om;
  uint64_t x;

  unsigned char buf[128];
  memset((char *)buf, 0, 128);

  if (n <= 64) // the minimal subChunk Size.
    return n;
  else
    i = 64;
  windows_reset();
  while (i <= n) {
    SLIDE(p[i - 1], fingerprint, bufPos, buf);
    if (i <= 512) // the average chunk size
    {
      w_digest = (fingerprint & subChunk_sizeA);
    } else {
      w_digest = (fingerprint & subChunk_sizeB); /*something wrong?*/
    }
    if (w_digest == BREAKMARK_VALUE || i >= max_subChunk_size || i == n)
      break;
    i++;
  }
  return i;
}

int rabin_delta(unsigned char *p, int n) {

  uint64_t f_break = 0;
  uint64_t count = 0;
  uint64_t fingerprint = 0, w_digest;
  int i = 1, bufPos = -1, stati = 0, minflag = 0;

  unsigned char om;
  uint64_t x;

  unsigned char buf[128];
  memset((char *)buf, 0, 128);

  if (n <= 32)
    return n;
  else
    i = 32;
  windows_reset();
  /**/
  for (int j = 32; j >= 2; j--) {
    SLIDE(p[i - j], fingerprint, bufPos, buf);
  }
  while (i < n) {

    SLIDE(p[i - 1], fingerprint, bufPos, buf);
    // Finger[(fingerprint>>28)&16383]++;

    if (((fingerprint & STRAVG) == 0x3) || i >= STRMAX) {
      break;
    } else
      i++;
  }

  return i;
}

long int MiAi[256][2] = {
    5652377,    45673472, 24423617, 146512310, 16341615,  142364781, 3526234,
    1225434201, 654410,   324130,   3124312,   359840125, 35,        15254201,
    61,         41870,    212,      3340125,   121,       44122,     551,
    8431641,    610,      824311,   367,       254201,    651,       7632410,
    319,        7540125,  129,      115422,    551,       34431741,  633,
    424311,     11,       31,       17,        5,         23,        37,
    71,         97,       37,       241,       247,       257,       137,
    2391,       431,      831,      2137,      4313,      173,       3022467,
    523,        4507221,  753,      6750467,   143,       412234,    372,
    3174123,    637,      324123,   821,       25420451,  107,       31023,
    423,        3512545,  667,      1541242,   851,       843541741, 453,
    3244311,    964,      223401,   910,       3233410,   223,       354012523,
    827,        12322,    751,      843178741, 456,       438911,
};

#define SAMPLE_GEAR 0x0000500303510000LL
//#define SAMPLE_GEAR  0x00000000000001ffLL



int boxcar_delta(unsigned char *p, int n) {
  uint64_t fingerprint = 0, w_digest;
  int i = 1;

  if (n <= 32) // the minimal  subChunk Size.
    return n;
  else
    i = 32;
  windows_reset();
  for (int j = 1; j <= 32; j++) {
    fingerprint += GEAR[p[i - j]];
  }
  while (i < n) {
    fingerprint += GEAR[p[i]] - GEAR[p[i - 32]];
#if 0				
		if( i < DMEANSIZE) // the average chunk size
		{		    
			if( (fingerprint & subChunk_sizeA) == BREAKMARK_VALUE)
				break;
		}
		else  
		{
			if( (fingerprint & subChunk_sizeB) == BREAKMARK_VALUE || i >= max_subChunk_size )
				break;
		}		
		i++;
#else
    if ((!(fingerprint & 63)) || i > 256) {
      break;
    }

    i++;
#endif
  }
  // printf("\r\n==chunking FINISH!\r\n");
  return i;
}

int boxcar_data(unsigned char *p, int n) {
  uint64_t fingerprint = 0, w_digest;
  int i = 1;

  if (n <= min_chunk_size) // the minimal  subChunk Size.
    return n;
  else
    i = min_chunk_size;
  windows_reset();
  for (int j = 1; j <= 48; j++) {
    fingerprint += GEAR[p[i - j]];
  }
  while (i < n) {
    fingerprint += GEAR[p[i]] - GEAR[p[i - 48]];
    // Finger[fingerprint&16383]++;
#if 0		
		if( i <= box_chunk_size ) // the average chunk size
		{		    
			w_digest = (fingerprint & box_chunk_sizeA); 
		}
		else  
		{
			w_digest = (fingerprint & box_chunk_sizeB); 		
		}
		
		//printf("%d,",w_digest);
		if( w_digest==BREAKMARK_VALUE || i >= max_chunk_size || i==n )
			break;
		i++;
#else
    if ((!(fingerprint & rabin_chunk_size)) ||
        i > max_chunk_size /*GetUperBits(i,16) */) {
      break;
    } else
      i++;
#endif
  }
  // printf("\r\n==chunking FINISH!\r\n");
  return i;
}

int boxcar_delta_v2(unsigned char *p, int n, int *cut) {
  uint64_t fingerprint = 0;
  int i = 0, count = 0;
  cut[count++] = i;

  if (n <= 64) // the minimal  subChunk Size.
    return n;
  else
    i = 64;
  windows_reset();
  for (int j = 1; j <= 48; j++) {
    fingerprint += GEAR[p[i - j]];
  }
  while (i < n) {
    fingerprint += GEAR[p[i]] - GEAR[p[i - 48]];
    if ((!(fingerprint & 255) && i > (cut[count - 1] + 64)) ||
        i > (cut[count - 1] + 1024)) {
      cut[count++] = i;
    }
    i++;
  }
  if (n <= (cut[count - 1] + 64)) {
    count = count - 1;
  }
  // printf("\r\n==chunking FINISH!\r\n");
  cut[count] = i;
  return count;
}

int boxcar_delta_v3(unsigned char *p, int n, int *cut, uint64_t *Gear) {
  uint64_t fingerprint = 0;
  int i = 48, count = 0, LastPos = 16;
  cut[count++] = 0;
  if (n <= 48) {
    cut[count] = n;
    Gear[count] = GearHash(p, n);
    return count;
  }

  windows_reset();
  for (int j = 1; j <= 48; j++) {
    fingerprint += GEAR[p[i - j]];
  }
  while (i < n) {
    fingerprint = (fingerprint + GEAR[p[i]]) - GEAR[p[i - 48]];
    if (!(fingerprint & 255) && i > LastPos) {
      cut[count] = i;
      LastPos = i + 16;
      Gear[count++] = weakHash(p + i - 47, 48);
    }
    i++;
  }
  // printf("\r\n==chunking FINISH!\r\n");

  if (n < LastPos || n == LastPos - 16) {
    count = count - 1;
  }
  cut[count] = i;
  Gear[count] =
      weakHash(p + i - 47, 48); //(fingerprint+GEAR[p[i]]) - GEAR[p[i-48]];

  return count;
}

// 63 ,  32,  256
int boxcar_delta_v4(unsigned char *p, int n, int *cut) {
  uint64_t fingerprint = 0;
  int i = 32, count = 0;
  cut[count++] = 0;
  if (n <= dDelta_AVG_Size) {
    cut[count] = n;
    return count;
  }

  for (int j = 1; j <= 32; j++) {
    fingerprint += GEAR[p[i - j]];
  }
  while (i < n) {
    fingerprint = (fingerprint + GEAR[p[i]]) - GEAR[p[i - 32]];
    if ((!(fingerprint & 15) && i > (cut[count - 1] + 8)) ||
        i > (cut[count - 1] + 64)) {
      cut[count++] = i;
    }
    i++;
  }

  if (n < (cut[count - 1] + 8)) {
    count = count - 1;
  }
  cut[count] = i;

  return count;
}

int chunk_samplebyte(unsigned char *p, int n) {
  int avg = STRAVG + 1;
  int i = avg / 2;

  while (i < n) {
    if (SAMPLEBYTE[p[i]] == 1 || i > STRMAX)
      return i;
  }
  return n;
}

int rolling_samplebyte(unsigned char *p, int n, int *cut) {
  int i = 0, count = 0;
  cut[count++] = 0;
  int avg = STRAVG + 1;

  i += avg / 2;
  while (i < n) {
    if (SAMPLEBYTE[p[i]] == 1 || i > cut[count - 1] + STRMAX) {
      cut[count++] = i;
      i += avg / 2;
    } else {
      i++;
    }
  }
  cut[count] = n;

  return count;
}

// jump by STRMIN bytes
int chunk_gear(unsigned char *p, int n) {
  uint32_t fingerprint = 0;
  int i = STRMIN + 1;
  if (n <= STRMAX) {
    return n;
  }

  while (i <= n) {
    fingerprint = (fingerprint << 1) + GEAR[p[i]];
    if (i <= STRMAX) {
      if (!(fingerprint & STRAVG))
        return i;
    } else {
      return i;
    }
    i++;
  }
}

/* the gear chunking function */
/*
int rolling_gear(unsigned char *p, int n, int *cut)
{
        uint32_t fingerprint=0;
        int i=0,count=0;
        cut[count++] = 0;
        if(n<=STRMAX){
                cut[count] = n;
                return count;
        }

        while( i < n )
        {
                fingerprint = (fingerprint<<1) +GEAR[p[i]];
                if ( ( ( !(fingerprint & STRAVG )) && i > (cut[count-1] +
STRMIN))
                                || i > (cut[count-1] + STRMAX) ) {
                        cut[count++] = i;
                }
                i++;
    }

    if( n < (cut[count-1] + STRAVG)){
                count = count - 1;
    }
        cut[count] = i;

    return count;

}
*/

/*
//not jump
int rolling_gear(unsigned char *p, int n, int *cut)
{
        uint32_t fingerprint=0;
        int i=0,count=0;
        cut[count++] = 0;
        if(n<=STRMAX){
                cut[count] = n;
                return count;
        }

        while( i < n )
        {
                fingerprint = (fingerprint<<1) +GEAR[p[i]];
                if(i <= (cut[count-1] + STRMAX)){
                        if(( !(fingerprint & STRAVG )) && i > (cut[count-1] +
STRMIN)) cut[count++] = i;
                }
                else{
                        cut[count++] = i;
                }
                i++;
    }

    if( n < (cut[count-1] + STRAVG)){
                count = count - 1;
    }
        cut[count] = i;

    return count;

}
*/

#if 0

//jump by STRMIN bytes 
/* different of rolling_gear(), where @num_of_chunks indicates the number of 
 * chunks to chunk, instead of the number of bytes; and @return indicates the 
 * number of bytes it actually chunks.
 */
int rolling_gear_v2(unsigned char *p, int num_of_chunks, int *cut)
{
	uint32_t fingerprint=0;
	int i=0,count=0;
	cut[count++] = 0;

	i+=STRMIN+1;

	int j=0;
	while( j < num_of_chunks )
	{		
		fingerprint = (fingerprint<<1) +GEAR[p[i]];
		if(i <= (cut[count-1] + STRMAX)){
			if( !(fingerprint & STRAVG )){
				cut[count++] = i;
				i+=STRMIN;
				j++;
			}
		}
		else{
			cut[count++] = i;
			i+=STRMIN;
			j++;
		}
		i++;
    }
    
    return cut[count-1];
}

#endif

// jump by STRMIN bytes
/* different from rolling_gear_v2, where @n indicates the bytes left in @p that
 * can be chunked. And rolling_gear_v2 is abandoned.
 */
int rolling_gear_v3(unsigned char *p, int n, int num_of_chunks, int *cut) {
  uint32_t fingerprint = 0;
  int i = 0, count = 0;
  cut[count++] = 0;

  i += STRMIN + 1;

  int j = 0;
  while (j < num_of_chunks) {
    if (i < n) {
      fingerprint = (fingerprint << 1) + GEAR[p[i]];
      if (i <= (cut[count - 1] + STRMAX)) {
        if (!(fingerprint & STRAVG)) {
          /* this requires the last few bits of fingerprint to be all 0 */
          cut[count++] = i;
          i += STRMIN;
          fingerprint = 0;
          j++;
        }
      } else {
        cut[count++] = i;
        i += STRMIN;
        fingerprint = 0;
        j++;
      }
      i++;
    } else {
      while (j < num_of_chunks) {
        cut[count++] = n;
        j++;
      }

      break;
    }
  }

  return cut[count - 1];
}

// jump by STRMIN bytes
int rolling_gear(unsigned char *p, int n, int *cut) {
  uint32_t fingerprint = 0;
  int i = 0, count = 0;
  cut[count++] = 0;
  if (n <= STRMAX) {
    cut[count] = n;
    return count;
  }
  i += STRMIN + 1;

  while (i < n) {
    fingerprint = (fingerprint << 1) + GEAR[p[i]];
    if (i <= (cut[count - 1] + STRMAX)) {
      if (!(fingerprint & STRAVG)) {
        cut[count++] = i;
        i += STRMIN;
      }
    } else {
      cut[count++] = i;
      i += STRMIN;
    }
    i++;
  }

  if (n < (cut[count - 1] + STRAVG)) {
    count = count - 1;
  }
  cut[count] = i;

  return count;
}

/* the gear chunking function without min/max chunk size limitations */
int rolling_gear_wo_min_max(unsigned char *p, int n, int *cut) {
  uint32_t fingerprint = 0;
  int i = 0, count = 0;
  cut[count++] = 0;

  while (i < n) {
    fingerprint = (fingerprint << 1) + GEAR[p[i]];
    if (!(fingerprint & STRAVG)) {
      cut[count++] = i;
    }
    i++;
  }

  if (n < (cut[count - 1] + STRAVG)) {
    count = count - 1;
  }
  cut[count] = n;

  return count;
}

#define my_memcmp(x, y)                                                        \
  ({                                                                           \
    int __ret;                                                                 \
    uint64_t __a = __builtin_bswap64(*((uint64_t *)x));                        \
    uint64_t __b = __builtin_bswap64(*((uint64_t *)y));                        \
    if (__a > __b)                                                             \
      __ret = 1;                                                               \
    else                                                                       \
      __ret = -1;                                                              \
    __ret;                                                                     \
  })

/* the ae chunking function */
int rolling_ae(unsigned char *p, int n, int *cut) {
  /* avg_chunk_size = (e-1)*window_size */
  int avg = STRAVG + 1;
  int window_size = avg / 1.7183;
  int count = 0;
  cut[count++] = 0;

  unsigned char *p_curr, *max_str = p;
  int comp_res = 0;

  int i = 1; /* the cursor in @p */
  while (n - i > window_size + 8) {
    p_curr = p + i;
    comp_res = my_memcmp(p_curr, max_str);
    if (comp_res > 0) {
      max_str = p_curr;
      i++;
      continue;
    }

    if ((p_curr - max_str) == window_size) {
      cut[count++] = i + 1;
      max_str = p_curr + 1;
      i++;
    }
    i++;
  }

  cut[count] = n;

  return count;
}

int rolling_rabin(unsigned char *p, int n, int *cut) {
  uint64_t fingerprint = 0;
  int i = STRMAX, count = 0, LastPos = 16, bufPos = -1;
  cut[count++] = 0;
  if (n <= STRMAX) {
    cut[count] = n;
    return count;
  }
  for (int j = 32; j >= 2; j--) {
    SLIDE(p[i - j], fingerprint, bufPos, buf);
  }
  while (i < n) {
    SLIDE(p[i - 1], fingerprint, bufPos, buf);
    if (((!(fingerprint & STRAVG)) && i > (cut[count - 1] + STRMIN)) ||
        i > (cut[count - 1] + STRMAX)) {
      cut[count++] = i;
    }
    i++;
  }

  if (n < (cut[count - 1] + STRAVG)) {
    count = count - 1;
  }
  cut[count] = i;

  return count;
}

int rolling_fixed(unsigned char *p, int n, int *cut) {
  int count = 0;
  for (int i = 0; i < n; i += STRAVG + 1) {
    cut[count++] = i;
  }
  cut[count] = n;
  return count;
}

int adler32_delta_v1(unsigned char *p, int n, int *cut) {
  uint64_t fingerprint = 0;
  int i = 8, count = 0, LastPos = 16;
  cut[count++] = 0;
  if (n <= 64) {
    cut[count] = n;
    return count;
  }

  fingerprint = ADLER32_initial(&p[i - 8], 8);
  while (i < n) {
    fingerprint = ADLER32_update(fingerprint, &p[i - 8], 8);
    if ((!(fingerprint & 15) && i > (cut[count - 1] + 8)) ||
        i > (cut[count - 1] + 64)) {
      cut[count++] = i;
    }
    i++;
  }

  if (n < (cut[count - 1] + 64)) {
    count = count - 1;
  }
  cut[count] = i;

  return count;
}

int adler32_data(unsigned char *p, int n) {
  uint32_t fingerprint = 0;
  int i = 1, max = max_chunk_size < n ? max_chunk_size : n;

  if (n <= min_chunk_size) // the minimal  subChunk Size.
    return n;
  else
    i = min_chunk_size;

  fingerprint = ADLER32_initial(&p[i - 48], 48);
  while (i < max) {
#if 1
    fingerprint = ADLER32_update(fingerprint, &p[i - 48], 48);
#else
    // uint32_t old_c = adlerhash[(int) p[i-48]];
    // uint32_t new_c = adlerhash[(int) p[i]];
    uint32_t low = ((fingerprint >> 16) - p[i - 48] + p[i]) & 0xffff;
    uint32_t high = ((fingerprint & 0xffff) - (p[i - 48] * 48) + low) & 0xffff;
    fingerprint = (low << 16) | high;
#endif
    if (!(fingerprint & rabin_chunk_size)) {
      break;
    } else
      i++;
  }
  // printf("\r\n==chunking FINISH!\r\n");
  return i;
}

uint64_t GearHash(unsigned char *p, int len) {
  uint64_t hash1 = 0;
  int wSize = 48;
  if (len < 48)
    wSize = len;
  for (int k = 0; k < wSize; k++) {
    hash1 += GEAR[p[k]];
  }
  return hash1;
}

int fastcdc_chunk_data(unsigned char *p, int n) {
  assert(p != NULL);
  uint64_t fp = 0;
  if (n < STRMAX) {
    if (n <= STRMIN) {
      return n;
    } else if (n < STRAVG) {
      for (int i = STRMIN; i < n; i++) {
        fp = (fp << 1) + GEAR[p[i]];
        if (!(fp & g_condition_mask[Mask_256B])) {
          return i;
        }
      }
      return n;
    } else {
      for (int i = STRMIN; i < STRAVG; i++) {
        fp = (fp << 1) + GEAR[p[i]];
        if (!(fp & g_condition_mask[Mask_256B])) {
          return i;
        }
      }
      for (int i = STRAVG; i < n; i++) {
        fp = (fp << 1) + GEAR[p[i]];
        if (!(fp & g_condition_mask[Mask_256B])) {
          return i;
        }
      }
      return n;
    }
  }
  for (int i = STRMIN; i < STRAVG; i++) {
    fp = (fp << 1) + GEAR[p[i]];
    if (!(fp & g_condition_mask[Mask_256B])) {
      return i;
    }
  }
  for (int i = STRAVG; i < STRMAX; i++) {
    fp = (fp << 1) + GEAR[p[i]];
    if (!(fp & g_condition_mask[Mask_256B])) {
      return i;
    }
  }
  return STRMAX;
}

int rolling_fastCDC(unsigned char *p, int n, int *cut) {
  int i = 0, count = 0;
  int lesslength = n - i;
  cut[count++] = 0;
  if (n <= STRMAX) {
    cut[count] = n;
    return count;
  }

  while (i < n) {
    int chunksize = fastcdc_chunk_data(p + i, lesslength);
    i += chunksize;
    lesslength = n - i;
    cut[count++] = i;
  }
  count--;

  if (n < (cut[count - 1] + STRMIN)) {
    count = count - 1;
  }
  cut[count] = i;

  return count;
}
