/** 
 * @Author: Wang Haitao
 * @Date: 2022-02-20 23:00:21
 * @LastEditTime: 2022-02-20 23:00:22
 * @LastEditors: Wang Haitao
 * @FilePath: /edelta/util.h
 * @Description: Github:https://github.com/apple-ouyang 
 * @ Gitee:https://gitee.com/apple-ouyang
 */
#include <cstdint>

uint64_t weakHash(unsigned char *buf, int len){
   return XXH64(buf, len, 0x7fcaf1);
}