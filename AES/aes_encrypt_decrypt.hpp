#ifndef AES_ENCRYPT_DECRYPT_H_
#define AES_ENCRYPT_DECRYPT_H_

#include "my_util.hpp"
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
#include "cryptopp/gcm.h"
#include "cryptopp/xts.h"

using namespace CryptoPP;

#include "assert.h"

#define TAG_SIZE 16

class MyAES {
    private:
    byte* key;
    byte iv[AES::BLOCKSIZE];
    unsigned int key_size;

    public:

    MyAES(){
        this->key = new byte[32];
        this->key_size = 32;
    }

    MyAES(const int byte_of_key_size){
        this->key = new byte[byte_of_key_size];
        this->key_size = byte_of_key_size;
    }

    ~MyAES(){
        delete[] this->key;
    }

    void SetKeyFromHexString(const string& hex_string_key);
    void SetIVFromHexString(const string& hex_string_iv);

    void RandomKey();
    void RandomIV();
    void InputKey();
    void InputIV();
    void LoadKeyFromFile(const char* filename);
    void LoadIVFromFile(const char* filename);
    
    string Encryption(const string& plain_text, const int mode = 1);
    string Decryption(const string& cipher_text, const int mode = 1);
    string ByteToString(byte* value, const int size);
    string StringEncoded(const string& value);
    string StringDecoded(const string& value);
    
    string GetKey() {
        return this->ByteToString(this->key, this->key_size);
    }

    string GetIV() {
        return this->ByteToString(this->iv, sizeof(this->iv));
    }
};
#endif /* AES_ENCRYPT_DECRYPT_H_ */