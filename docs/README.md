# ECCPEM API Documentation

#### 1.`CreateECCKeysPemFiles`
Function generates Elliptic Curve Cryptography - ECC key pairs and writes to PEM formatted files.

**Arguments:**
- `ec_type`: Elliptic Curve type. To list the supported curves run:
             `$ openssl ecparam -list_curves` command.
- `pubkey_file`: PEM formatted file (extension is .pem) where is going to be
                 stored public key.
- `privkey_file`: PEM formatted file (extension is .pem) where is going to be
                  stored private key.

**Returns:**
- 1 if generation of key pairs and writing them to PEM files was successful.
- 0 if Creating a new OpenSSL EC_KEY object and writing to PEM files failed.


Function prototype:

```c
int CreateECCKeysPemFiles(const char* ec_type,
                          const char* pubkey_file,
                          const char* privkey_file);
```

---




#### 2. `ReadPrivateKeyPemFile`
Function reads private key's pem file and stores it in a given array as a binary data.


**Arguments:**
- `privkey_file`: PEM formatted file (extension is .pem) from where it is going
                  to be read private key and store in a array as a binary data.
- `private_key`: An array where is going to be stored private key.
- `key_size`: Size of array. Run `$ openssl ecparam -list_curves` command in
              order to see binary size of specific crypto algorithm.


**Returns:**
- `1` if readind pem file and storing data to array was successful.
- `0` if it cannot open provided PEM file or cannot read provided PEM file
      or fails to convert EVP_PKEY to EC_KEY or fails to convert bignum to
      binary.

Function prototype:
```c
int ReadPrivateKeyPemFile(const char* privkey_file,
                          uint8_t private_key[],
                          const unsigned int key_size);
```

---

