# ECCPEM Documentation

#### 1. `CreateECCKeysPemFiles`
```c
int CreateECCKeysPemFiles(const char* ec_type, const char* pubkey_file,  const char* privkey_file);
```
Function generates Elliptic Curve Cryptography (ECC) key pairs and writes them to PEM formatted files.

**Arguments:**
- `ec_type`: Elliptic Curve type. To list the supported curves run: `$ openssl ecparam -list_curves` command.
- `pubkey_file`: PEM formatted file (extension is .pem) where is going to be stored public key.
- `privkey_file`: PEM formatted file (extension is .pem) where is going to be stored private key.

**Returns:**
- 1 if generation of key pairs and writing them to PEM files was successful.
- 0 if Creating a new OpenSSL EC_KEY object and writing to PEM files failed.


---




#### 2. `ReadPrivateKeyPemFile`
```c
int ReadPrivateKeyPemFile(const char* privkey_file, uint8_t private_key[], const unsigned int key_size);
```
Function reads private key's PEM file and stores it in a given array as binary data.

**Arguments:**
- `privkey_file`: PEM formatted file (extension is .pem) from which the private key will be read and stored in an array as binary data.
- `private_key`: An array where the private key will be stored.
- `key_size`: Size of array. Run `$ openssl ecparam -list_curves` command to see the binary size of the specific cryptographic algorithm.


**Returns:**
- `1` if reading PEM file and storing data to array was successful.
- `0` if it cannot open the provided PEM file, cannot read the provided PEM file,
      fails to convert EVP_PKEY to EC_KEY, or fails to convert bignum to
      binary.


---




#### 3. `ReadPublicKeyPemFile`
```c
int ReadPublicKeyPemFile(const char* pubkey_file, uint8_t public_key[], const unsigned int compressed_key_size);
```
Function reads public key's PEM file and stores it in a given array as binary data.
Note that the array will contain a compressed public key.


**Arguments:**
- `pubkey_file`: PEM formatted file (extension is .pem) from which the public key will be read and stored in an array as binary data.
- `public_key`: An array where the compressed public key will be stored.
- `compressed_key_size`: Size of array. Basically compressed public key size is 33 byte.


**Returns:**
- `1` if reading PEM file and storing data to array was successful.
- `0` if it cannot open the provided PEM file, cannot read the provided PEM file,
      fails to convert EVP_PKEY to EC_KEY, or fails to read compressed EC public key.

---

