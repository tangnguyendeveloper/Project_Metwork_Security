//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include "cryptopp/integer.h"
using CryptoPP::Integer;
#include "cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;

#include "cryptopp/ecp.h"
#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include "cryptopp/pubkey.h"
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include "cryptopp/asn.h"
#include "cryptopp/oids.h" // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

int main(int argc, char* argv[]){

    Integer p("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377h");
    Integer a("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9h");
    Integer b("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6h");
    Integer x("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262h");
    Integer y("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997h");
    Integer n("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7h");
    Integer h("0x1");

    a %= p; b %= p;
    CryptoPP::ECP brainpoolP256_curve(p, a, b);
    ECP::Point G(x,y);

    CryptoPP::DL_GroupParameters_EC<ECP> curve256;
    curve256.Initialize(brainpoolP256_curve,G,n,h);

    CryptoPP::Integer k("27eb4fc6d174da93be8cba5d5ac3ae6ab884d8d1f1c06a2d38565a3a99fb0d5ah");

    ECP::Point U = curve256.GetCurve().Multiply(k, G);
    cout << "Ux=" << hex << U.x << endl;
    cout << "Uy=" << hex << U.y << endl;

    return 0;
}