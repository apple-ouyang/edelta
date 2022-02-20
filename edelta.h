/** 
 * @Author: Wang Haitao
 * @Date: 2022-02-20 22:16:29
 * @LastEditTime: 2022-02-20 22:56:26
 * @LastEditors: Wang Haitao
 * @FilePath: /edelta/edelta.h
 * @Description: Github:https://github.com/apple-ouyang 
 * @ Gitee:https://gitee.com/apple-ouyang
 */
#pragma once

#include <cstdint>

#include "htable.h"
#include "parameters.h"

typedef struct       
{
	//char 		szData[SUBCHUNK_DEFAULT_SIZE];	
	uint64_t 	nHash; // the chunk fingerprint
	//uint64_t 	nGear; //the hash of  the last CDC window
	
	uint32_t 	nOffset;//the offset of the string in the chunk
	/* the first character of the string is **buf[nOffset], and 
	* there're nOffset characters before the string in the **buf.
	*/
	uint32_t 	nLength;//string length
	uint16_t 	DupFlag; // 1 dup, 0 sim, 2 beg or end
	uint32_t 	nSimID; /* used in the input chunk/file to indicate which string in the 
						* base chunk/file it is indentical to
						*/
	hlink   	  psNextSubCnk;
}DeltaRecord;// to a string

/* to represent an identical string to the base, 8 bytes, flag=0 */
typedef struct        /* the least write or read unit of disk */   
{
	uint32_t	flag_length; //flag & length
	/* the first bit for the flag, the other 31 bits for the length */

	uint32_t 	nOffset;
}DeltaUnit1;

/* to represent an  string not identical to the base, 4 bytes, flag=1 */
typedef struct        /* the least write or read unit of disk */
{
	uint32_t 	flag_length; //flag & length
	/* the first bit for the flag, the other 31 bits for the length */
}DeltaUnit2; 

int eDelta_Encode( uint8_t* newBuf, uint32_t newSize,
		  				uint8_t* baseBuf, uint32_t baseSize,
		  				uint8_t* deltaBuf, uint32_t *deltaSize );	
    
int dDelta_Decode(uint8_t *deltaBuf, uint32_t deltaSize,
                  uint8_t *baseBuf, uint32_t baseSize,
                  uint8_t *outBuf, uint32_t *outSize);