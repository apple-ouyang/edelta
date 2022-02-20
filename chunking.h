/* chunking.h
the main fuction is to chunking the file!
*/
#include <cstdint>

//#define INT64(n) n##LL
#define MSB64 0x8000000000000000LL
#define MAXBUF (128*1024) 


#define FINGERPRINT_PT  0xbfe6b8a5bf378d83LL
#define BREAKMARK_VALUE 0x78
#define BREAKMARK_BACKUP 0x79
#define MIN_CHUNK_SIZE  2048
#define MAX_CHUNK_SIZE  65536



//#define NUMFEATURE 4

#define GSIZE32BIT  0xffffffffLL
	
//uint64_t polymmult(uint64_t x, uint64_t y, uint64_t d);

//uint64_t polymod(uint64_t nh, uint64_t nl, uint64_t d);

//uint64_t append8(uint64_t p, UCHAR m);


//uint64_t polymmult(uint64_t x, uint64_t y, uint64_t d);

//void Rabin_init(uint64_t poly);

//void Rabin_reset();


int chunk_data(unsigned char *p, int n);

int chunk_data_delta(unsigned char *p, int n);

int rabin_delta(unsigned char *p, int n);

void chunkAlg_init_edelta();

void windows_reset();

void Super_feature_speed(char *path, int number, int number2, int flag);

void Super_feature_test(unsigned char *p, int n, uint64_t SF[], int number, int number2);

void Super_feature_SGear(unsigned char *p, int n, uint64_t SF[], int number, int number2);

void Super_feature(unsigned char *p, int n, uint64_t SF[], int number, int number2);

void Super_feature2(unsigned char *p, int n, uint64_t SF[], int number);

void Super_feature3(unsigned char *p, int n, uint64_t SF[], int number);

void TestRabin();


void TestRabin();

void INT64toString(uint64_t A, char * string );

int boxcar_delta(unsigned char *p, int n);

int boxcar_data(unsigned char *p, int n);

int boxcar_delta_v2(unsigned char *p, int n, int *cut);

int boxcar_delta_v3(unsigned char *p, int n, int *cut, uint64_t *Gear);
\
int boxcar_delta_v4(unsigned char *p, int n, int *cut);

int rolling_gear(unsigned char *p, int n, int *cut);

int rolling_gear_v2(unsigned char *p, int num_of_chunks, int *cut);

int rolling_gear_v3(unsigned char *p, int n, int num_of_chunks, int *cut);

int rolling_fixed(unsigned char *p, int n, int *cut);

int rolling_gear_wo_min_max(unsigned char *p, int n, int *cut);

int rolling_ae(unsigned char *p, int n, int *cut);

int chunk_gear(unsigned char *p, int n);

int chunk_samplebyte(unsigned char *p, int n);

int rolling_samplebyte(unsigned char *p, int n, int *cut);

int rolling_rabin(unsigned char *p, int n, int *cut);

int adler32_data(unsigned char * p, int n);
int rolling_fastCDC(unsigned char *p, int n, int *cut);

int fastcdc_chunk_data(unsigned char *p, int n);

 inline int rolling_data(unsigned char * p, int n)
 {
	 uint32_t fingerprint=0,w_digest;
	 int i=1;		  
  
	 if(n<=MIN_CHUNK_SIZE) //the minimal  subChunk Size.
		 return n;
	 else
		 i=MIN_CHUNK_SIZE;
	 //windows_reset();
	
	 while(i<n	)
	 {		 
		 fingerprint = (fingerprint<<1)+(p[i]+1);
		 //Finger[fingerprint&16383]++;
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
		 if ( (!(fingerprint & 8191) )
					 || i > MIN_CHUNK_SIZE*32/*GetUperBits(i,16) */) {
			 break;
		 }
		 else
			 i++;		 
#endif
	 }
	 //printf("\r\n==chunking FINISH!\r\n");
	 return i;
 }



uint64_t GearHash(unsigned char * p, int len);

int adler32_delta_v1(unsigned char *p, int n, int *cut);

