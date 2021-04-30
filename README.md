[![Build Status](https://travis-ci.com/baloyan/eccpem.svg?branch=master)](https://travis-ci.com/baloyan/eccpem)
--------------------------------

# ECCPEM
How to generate Elliptic Curve Cryptography (ECC) key pairs (public and private
keys) write them in PEM file or read from PEM file in C and C++ programming
languages?

ECCPEM library makes it super easy just invoking one function and the job is done!

### Get the source code and build the project

Before installing the project, install minimum requirements: `Cmake` and `OpenSSL` libraries.
```bash
$ sudo apt-get instal cmake libssl-dev
```

Use `git` from the command-line to clone the source code:

```bash
$ git clone https://github.com/baloyan/eccpem.git
$ cd eccpem
```

To configure and build the project run the following commands:

```bash
$ mkdir build
$ cd build

$ cmake ..
$ make
$ sudo make install
```

### How to use ECCPEM ?
Using ECCPEM is pretty easy just include corresponding header file
(`#include <eccpem/eccpem>`) and use `-leccpem` compiler option.
Note that as ECCPEM is based on OpenSSL library you should also use
`-lssl` and `-lcrypto` options just next to the `-leccpem`.

In this example we are generating `secp256k1` Elliptic Curve type (Bitcoin uses
the same). To list the supported curves run  `$ openssl ecparam -list_curves`
command.

Example:

Create a `eccpem_test.c` file and write the following code:
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


Compile the above code:
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

### ECCPEM API

For detailed ECCPEM API documentation take a look at [eccpem/docs](
https://github.com/baloyan/eccpem/blob/master/docs/README.md)

### Contributions
Contributions can be made by submitting GitHub pull requests to this
repository.  In general, the ECCPEM source code follows Google's [C++ style
guide](https://google.github.io/styleguide/cppguide.html). (Yes, it is
for C++, but please follow rules for C language also).

### License
All contributions are made under the MIT license.  See [LICENSE](
https://github.com/baloyan/eccpem/blob/master/LICENSE).

### References
[1] [Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)   
[2] [OpenSSL Library](https://www.openssl.org/)   
[3] [Bitcoin Wiki](https://en.bitcoin.it/wiki/Secp256k1)   
[4] [How To Generate Public and Private Keys for the Blockchain](https://medium.com/@baloian/how-to-generate-public-and-private-keys-for-the-blockchain-db6d057432fb?fbclid=IwAR0u1yB39cgsPzYqYeHTe_ck7smi5PyShTCI2VKWpTW14wgkCiYGWL9axf0)
