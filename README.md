# Description
Edelta is a faster delta compression algorithem. It is proposed by Wen Xia in the [Edelta: A Word-Enlarging Based Fast Delta Compression Approach](https://www.usenix.org/conference/hotstorage15/workshop-program/presentation/xia)

# Build
```sh
mkdir -p build && cd build
cmake ..
make -j
```

# Test
I write the testing code based on the boost and googletest library.

So you should install them first.
## boost
You can install boost on Ubuntu like this:
```sh
sudo apt install libboost-filesystem 
```
## googletest
You can install googletest framework in any Linux distributions like this:
```sh
git clone git://github.com/google/googletest
cd googletest
mkdir -p build && cd build
make
sudo make install
```
## build
you should add `ENABLE_TEST` option to run cmake.
There is two ways:
1. run `ccmake ..`, and set `ENABLE_TEST` to ON.
2. run cmake like this:
```sh
cmake .. -DENABLE_TEST=ON
make -j
```
Then, you can run the `encode-decode-test` in the `build/tests` like this:
```sh
tests/encode-decode-test
```
After running the tests, enter a folder.  

The test program iterates through all the files in the folder, using the first one found as the base file and the others as the input files.  

It will check every input files will be the same after encoding and decoding.
# Author
The code came from the research group. I sorted it out and opened source it with permission.  
I made the following changes based on the source code: 
1. Fix some warnings
2. Select the final version from multiple versions of edelta.
3. Add a unit tests based on the googletest framework.  