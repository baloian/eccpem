# ECCPEM
Do you want to generate Elliptic Curve Cryptography (ECC) key pairs (public and private keys), write them to a .PEM file,
or read them from a .PEM file in C/C++ programming languages?

The ECCPEM library makes it super easy by invoking just one function and the job is done!

## Build
Before installing the project, make sure you have installed the minimum requirements: the `CMake` and `OpenSSL` libraries.
```bash
sudo apt-get install cmake libssl-dev
```

Use `git` from the command line to clone the source code:

```bash
git clone https://github.com/baloyan/eccpem.git
cd eccpem
```

To configure and build the project, run the following commands:

```bash
mkdir build
cd build

cmake ..
make
sudo make install
```

## Usage
As an example, create a `eccpem_test.c` file and write the following code:
```cpp
#include <eccpem/eccpem.h>
#include <stdio.h>

int main() {

  const char* pubkey_file = "pub_key.pem";
  const char* privkey_file = "priv_key.pem";

  const char* ec_type = "secp256k1";

  const int error_code = CreateECCKeysPemFiles(ec_type, pubkey_file, privkey_file);
  if (error_code == 1) {
    printf("Generation of ECC key pairs was successful.\n");
  } else {
    printf("Generation of ECC key pairs failed.\n");
  }

  return 0;
}
```


Compile the above code (`gcc` for C, `g++` for C++):
```bash
gcc -o myeccpem eccpem_test.c -leccpem -lssl -lcrypto
```
Run executable file:
```bash
./myeccpem
```

See C++ example: [cpp_gen_pem_files.cpp](https://github.com/baloian/eccpem/blob/master/examples/cpp_gen_pem_files.cpp)


## ECCPEM API
For detailed the ECCPEM API documentation take a look at [eccpem/docs](
https://github.com/baloyan/eccpem/blob/master/docs/README.md)


## Contributions
Contributions can be made by submitting GitHub pull requests to this
repository. In general, the ECCPEM source code follows Google's [C++ style
guide](https://google.github.io/styleguide/cppguide.html). (Yes, it is
for C++, but please follow the rules for C language as well).


## License
All contributions are made under the MIT license. See [LICENSE](https://github.com/baloyan/eccpem/blob/master/LICENSE).
