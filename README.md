[![Build Status](https://travis-ci.org/baloyan/eccpem.svg?branch=master)](https://travis-ci.org/baloyan/eccpem)
--------------------------------

# ECCPEM
How to generate Elliptic Curve Cryptography (ECC) key pairs (public and private
keys) write them in PEM file or read from PEM file in C and C++ programming
languages ?

ECCPEM library makes it super easy just calling one function and job is done!.

# Get the source code and build the project

Before installing project install minimum requirements, which are `Cmake` and
`OpenSSL` library.
```bash
$ sudo apt-get instal cmake libssl-dev
```

The latest source code is available on ECCPEM's GitHub repository. You may
use Git from the command-line to clone the source code:

```bash
$ git clone https://github.com/baloyan/eccpem.git
$ cd eccpem
```

To configure and build the project:

```bash
$ mkdir build
$ cd build

$ cmake ..
$ make
$ sudo make install
```

# How to use ECCPEM ?
Using ECCPEM is pretty easy just include corresponding header file
(`#include <eccpem/eccpem>`) and use `-leccpem` compiler option.
Note that as ECCPEM is based on OpenSSL library you should also use
`-lssl` and `-lcrypto` options just next to the `-leccpem`.

In this example we are generating `secp256k1` Elliptic Curve type (Bitcoin uses
the same). To list the supported curves run : `$ openssl ecparam -list_curves`
command.

Example:

Create a `eccpem_test.c` file and write following code:
```bash
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
    printf("Generation of ECC key pairs filed.\n");
  }

  return 0;
}
```


Compile code:
```bash
$ gcc -o myeccpem eccpem_test.c -leccpem -lssl -lcrypto
```
Run executable file:
```bash
$ ./myeccpem
```

C++ version of example, see: [cpp_gen_pem_files.cpp](
https://github.com/baloyan/eccpem/blob/master/tests/cpp_eccpem_test.cpp)

Compile C++ code:
```bash
$ g++ -o myeccpem cpp_eccpem_test.cpp -leccpem -lssl -lcrypto
```

# ECCPEM API

For detailed ECCPEM API documentation have look at [eccpem/docs](
https://github.com/baloyan/eccpem/blob/master/docs/README.md)

# Contributions
Contributions can be made by submitting GitHub pull requests to this
repository.  In general, the ECCPEM source code follows Google's [C++ style
guide](https://google.github.io/styleguide/cppguide.html). (Yes, it is
for C++, but please follow rules for C language also).

# License
All contributions are made under the MIT license.  See [LICENSE](
https://github.com/baloyan/eccpem/blob/master/LICENSE).

