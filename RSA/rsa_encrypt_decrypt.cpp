#include "rsa_encrypt_decrypt.hpp"

MyRSA::MyRSA(){
    this->private_key = new RSA::PrivateKey();
    this->public_key = new RSA::PublicKey();
}

MyRSA::MyRSA(bool random_key) {
    if (random_key){
        this->GenerateRandomKey();
    }
    else {
        this->private_key = new RSA::PrivateKey();
        this->public_key = new RSA::PublicKey();
    }
}

MyRSA::~MyRSA(){
    delete this->private_key;
    delete this->public_key;
}

void MyRSA::GenerateRandomKey(){
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(this->rng, 4096);

    this->private_key = new RSA::PrivateKey(parameters);
    this->public_key = new RSA::PublicKey(parameters);
    this->SavePrivateKey();
    this->SavePublicKey();
}

void MyRSA::LoadPrivateKey(const char* filename)
{
    delete this->private_key;
    this->private_key = new RSA::PrivateKey();

	ByteQueue queue;
	this->Load(filename, queue);
	this->private_key->Load(queue);	
}

void MyRSA::LoadPublicKey(const char* filename)
{
    delete this->public_key;
    this->public_key = new RSA::PublicKey();

	ByteQueue queue;
	this->Load(filename, queue);
	this->public_key->Load(queue);	
}

void MyRSA::Load(const char* filename, BufferedTransformation& bt)
{
	FileSource file(filename, true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void MyRSA::Save(const char* filename, const BufferedTransformation& bt){
    FileSink file(filename);

    bt.CopyTo(file);
    file.MessageEnd();
}

void MyRSA::SavePublicKey(const char* filename){
    ByteQueue queue;
    this->public_key->Save(queue);

    this->Save(filename, queue);
}

void MyRSA::SavePrivateKey(const char* filename){
    ByteQueue queue;
    this->private_key->Save(queue);

    this->Save(filename, queue);
}

string MyRSA::Encyption(const string& plaintext){
    string cipher;
    try {
        RSAES_OAEP_SHA_Encryptor encryptor(*this->public_key);
        StringSource( plaintext, true,
            new PK_EncryptorFilter(this->rng, encryptor,
                new StringSink(cipher)
            )
         );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    return cipher;
}

string MyRSA::Decryption(const string& ciphertext){
    string plain;
    try {
        RSAES_OAEP_SHA_Decryptor decryptor(*this->private_key);
        StringSource( ciphertext, true,
            new PK_DecryptorFilter( rng, decryptor,
                new StringSink(plain)
            )
         );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    return plain;
}

string MyRSA::StringEncoded(const string& value){
    string encoded;
    StringSource(value, true,
		new HexEncoder(
			new StringSink(encoded)
		)
	);
    return encoded;
}

string MyRSA::StringDecoded(const string& value){
    string decoded;
    StringSource(value, true,
		new HexDecoder(
			new StringSink(decoded)
		)
	);
    return decoded;
}
