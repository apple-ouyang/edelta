/** 
 * @Author: Wang Haitao
 * @Date: 2022-02-21 15:01:35
 * @LastEditTime: 2022-02-21 19:47:16
 * @LastEditors: Wang Haitao
 * @FilePath: /edelta/encode-decode-test.cpp
 * @Description: Github:https://github.com/apple-ouyang 
 * @ Gitee:https://gitee.com/apple-ouyang
 */

#include "src/edelta.h"
#include "boost/filesystem.hpp"
#include <iterator>
#include <string>
#include "gtest/gtest.h"
using namespace std;
namespace fs = boost::filesystem;
TEST(EdeltaTest, SpesificDirectory){
  cout << "input a directory:";
  string inp;
  cin >> inp;
  fs::path p(inp);
  ASSERT_TRUE(exists(p)) << "path:" << p << "doesn't exist!";
  ASSERT_TRUE(is_directory(p)) << "path:" << p << "is not a directory!";

  bool first = true;
  string base;

  for(fs::recursive_directory_iterator end, it(p); it!=end; ++it){
    if(is_directory(it->path()))
      continue;
    
    ifstream in(it->path().string());
    istreambuf_iterator<char> begin(in), endd;
    string read(begin, endd);

    if(first){
      base = read;
      first = false;
      cout << "base file path:" << it->path() << endl;
      // cout << "base:  \"" << base.substr(0, 20)  << "\"" << endl;
    }else{
      string input = read;
      if(input.empty()) continue;
      cout << "encode file path:" << it->path() << endl;
      // cout << "input: \""<< input.substr(0, 20) << "\"" << endl;

      const size_t kMaxLength = input.size() * 2;
      char* delta = new char[kMaxLength];
      char* output = new char[kMaxLength];
      uint32_t delta_size, output_size;
      
      EDeltaEncode((uint8_t *)input.data(), (uint32_t)input.size(), (uint8_t *)base.data(), (uint32_t)base.size(), (uint8_t *)delta, (uint32_t *)&delta_size);

      EDeltaDecode((uint8_t *)delta, delta_size, (uint8_t *)base.data(), (uint32_t)base.size(), (uint8_t *)output, &output_size);

      EXPECT_EQ(input.size(), output_size) << "input path:" << it->path() << " base path:" << base; 
      // EXPECT_STREQ(input.data(), output);

      delete [] delta;
      delete [] output;
    }
  }
}