#ifndef MY_ECDSA_H_
#define MY_ECDSA_H_

#include "my_util.hpp"

#include "cryptopp\osrng.h"
#include "cryptopp\aes.h"
#include "cryptopp\integer.h"
#include "cryptopp\sha3.h"
#include "cryptopp\filters.h"
#include "cryptopp\files.h"
#include "cryptopp\eccrypto.h"
#include "cryptopp\oids.h"
#include "cryptopp/asn.h"
#include "cryptopp/hex.h"

namespace ASN1 = CryptoPP::ASN1;
using namespace CryptoPP;
typedef DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;

string H(const string& value);

bool GenerateKey(ECDSA<ECP, SHA3_256>::PrivateKey& privateKey, ECDSA<ECP, SHA3_256>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA3_256>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA3_256>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA3_256>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA3_256>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA3_256>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA3_256>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA3_256>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA3_256>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA3_256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA3_256>::PublicKey& key, const string& message, const string& signature );


#endif /* MY_ECDSA_H_ */