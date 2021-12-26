#ifndef RSA_ENCRYPT_DECRYPT_H_
#define RSA_ENCRYPT_DECRYPT_H_

#include "my_util.hpp"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/SecBlock.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/queue.h"

using namespace CryptoPP;

class MyRSA {
    private:
    RSA::PublicKey* public_key;
    RSA::PrivateKey* private_key;
    AutoSeededRandomPool rng;

    void Load(const char* filename, BufferedTransformation& bt);
    void Save(const char* filename, const BufferedTransformation& bt);

    public:

    MyRSA();
    MyRSA(bool random_key);
    ~MyRSA();

    void LoadPrivateKey(const char* filename);
    void LoadPublicKey(const char* filename);
    void SavePublicKey(const char* filename="rsa-public.key");
    void SavePrivateKey(const char* filename="rsa-private.key");

    void GenerateRandomKey();

    string Encyption(const string& plaintext);
    string Decryption(const string& ciphertext);

    string StringEncoded(const string& value);
    string StringDecoded(const string& value);

};

#endif /* RSA_ENCRYPT_DECRYPT_H_ */