#include "my_ecdsa.hpp"


string H(const string& value){
    string digest;
    SHA3_256 hash;
    hash.Update((const byte*)value.data(), value.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    string encoded;
    StringSource(digest, true,
		new HexEncoder(
			new StringSink(encoded)
		)
	);
    return encoded;
}

bool GenerateKey(ECDSA<ECP, SHA3_256>::PrivateKey& privateKey, ECDSA<ECP, SHA3_256>::PublicKey& publicKey ){
    AutoSeededRandomPool prng;
    GroupParameters group;
    group.Initialize(ASN1::brainpoolP256r1());

    Integer x(prng, Integer::One(), group.GetMaxExponent());
    Element y = group.ExponentiateBase(x);

    privateKey.Initialize(group, x);
    assert( privateKey.Validate( prng, 3 ) );
    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA3_256>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA3_256>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << hex << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << hex << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << hex << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << hex << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << hex << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << hex << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << hex << params.GetCofactor() << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA3_256>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << hex << key.GetPrivateExponent() << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA3_256>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << hex << key.GetPublicElement().x << endl; 
    cout << " Y: " << hex << key.GetPublicElement().y << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA3_256>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA3_256>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA3_256>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA3_256>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA3_256>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();
    /*
    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA3_256>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    */

    string hash_mess = H(message) + "h";
    Integer h_m(hash_mess.c_str());
    Integer k, r, hm_rd, s;

    ECP::Point G = key.GetGroupParameters().GetSubgroupGenerator();
    ECP::Point kG;

    do {
        k = Integer(prng, Integer::One(), key.GetGroupParameters().GetSubgroupOrder() - Integer::One());
        kG = key.GetGroupParameters().GetCurve().Multiply(k, G);
        r = kG.x;
        hm_rd = h_m + (key.GetPrivateExponent() * r);
        s = k.InverseMod(key.GetGroupParameters().GetSubgroupOrder());
        s = (s * hm_rd).Modulo(key.GetGroupParameters().GetSubgroupOrder());

    }while (r.Modulo(key.GetGroupParameters().GetSubgroupOrder()).IsZero() || s.IsZero());


    stringstream ss_r, ss_s;
    ss_r << hex << r;
    ss_s << hex << s;
    signature = ss_r.str() + ":" + ss_s.str();
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA3_256>::PublicKey& key, const string& message, const string& signature )
{
    //bool result = false;
    /*
    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA3_256>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );
    */

    string delimiter = ":";
    Integer r(signature.substr(0, signature.find(delimiter)).c_str());
    Integer s(signature.substr(signature.find(delimiter) + delimiter.length(), signature.length()).c_str());
    Integer w = s.InverseMod(key.GetGroupParameters().GetSubgroupOrder());
    string hash_mess = H(message) + "h";
    Integer u1 = (Integer(hash_mess.c_str()) * w).Modulo(key.GetGroupParameters().GetSubgroupOrder());
    Integer u2 = (r * w);//.Modulo(key.GetGroupParameters().GetSubgroupOrder());

    ECP::Point G = key.GetGroupParameters().GetSubgroupGenerator();
    ECP::Point Q = key.GetPublicElement();
    ECP::Point u1G = key.GetGroupParameters().GetCurve().Multiply(u1, G);
    ECP::Point u2Q = key.GetGroupParameters().GetCurve().Multiply(u2, Q);
    ECP::Point V = key.GetGroupParameters().GetCurve().Add(u1G, u2Q);

    return V.x == r;
}