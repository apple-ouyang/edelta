/** 
 * @Author: Wang Haitao
 * @Date: 2022-02-20 22:16:29
 * @LastEditTime: 2022-02-23 16:48:22
 * @LastEditors: Wang Haitao
 * @FilePath: /titan/third-party/edelta/src/edelta.h
 * @Description: Github:https://github.com/apple-ouyang 
 * @ Gitee:https://gitee.com/apple-ouyang
 */
#pragma once

#include <cstdint>

#include "htable.h"
#include "util.h"

// Attention! input should not be empty! base should not be empty!
int EDeltaEncode( uint8_t* input, uint32_t input_size,
		  				uint8_t* base, uint32_t base_size,
		  				uint8_t* delta, uint32_t *delta_size );	
    
int EDeltaDecode(uint8_t *delta, uint32_t delta_size,
                  uint8_t *base, uint32_t base_size,
                  uint8_t *output, uint32_t *output_size);