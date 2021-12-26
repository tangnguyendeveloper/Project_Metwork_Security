
#include "aes_encrypt_decrypt.hpp"

void MyAES::SetKeyFromHexString(const string& hex_string_key) {
    string skey = hex_to_string(hex_string_key);
    if (skey.length() == this->key_size){
        StringSource ss(skey, false);
	    CryptoPP::ArraySink copykey(this->key, this->key_size);
	    ss.Detach(new Redirector(copykey));
	    ss.Pump(this->key_size);
    }
    else wcerr << "Key must be " << this-key_size << " bytes \n";
}

void MyAES::SetIVFromHexString(const string& hex_string_iv) {
    string siv = hex_to_string(hex_string_iv);
    if (siv.length() == sizeof(this->iv)){
        StringSource ss(siv, false);
	    CryptoPP::ArraySink copyiv(this->iv, sizeof(this->iv));
	    ss.Detach(new Redirector(copyiv));
	    ss.Pump(sizeof(this->iv));
    }
    else wcerr << "IV must be " << sizeof(this->iv) << " bytes \n";
}


void MyAES::RandomKey(){
    AutoSeededRandomPool prng;
    prng.GenerateBlock(this->key, this->key_size);
	StringSource ss(this->key, this->key_size, true , new FileSink( "AES_key_Random.key"));
}

void MyAES::RandomIV(){
    AutoSeededRandomPool prng;
    prng.GenerateBlock(this->iv, sizeof(this->iv));
	StringSource ss(this->iv, sizeof(this->iv), true , new FileSink( "AES_IV_Random.iv"));
}

void MyAES::InputKey(){
    wstring wskey;
	wcout << "Please input key " << this->key_size << " bytes:  ";
	wcin.ignore();
	getline(wcin,wskey);
	string skey;
	skey = wstring_utf8_to_string(wskey);
	StringSource ss(skey, false);
	CryptoPP::ArraySink copykey(this->key, this->key_size);
	ss.Detach(new Redirector(copykey));
	ss.Pump(this->key_size);
}

void MyAES::InputIV(){
    wstring wsiv;
    wcout << "Please input IV 16 bytes:  ";
    wcin.ignore();
	getline(wcin,wsiv);
	string siv;
	siv = wstring_utf8_to_string(wsiv);
    StringSource ss(siv, false);
	CryptoPP::ArraySink copyiv(this->iv, sizeof(this->iv));
	ss.Detach(new Redirector(copyiv));
	ss.Pump(sizeof(this->iv));
}

void MyAES::LoadKeyFromFile(const char* filename){
	FileSource fs(filename, false);
	CryptoPP::ArraySink copykey(this->key, this->key_size);
	fs.Detach(new Redirector(copykey));
	fs.Pump(this->key_size);
}

void MyAES::LoadIVFromFile(const char* filename){
    FileSource fs(filename, false);
	CryptoPP::ArraySink copyiv(this->iv, sizeof(this->iv));
	fs.Detach(new Redirector(copyiv));
	fs.Pump(sizeof(this->iv));
}

string MyAES::Encryption(const string& plain_text, const int mode){
    
    string cipher_text;

    try
    {
        
        if (mode == 1){
            wcout << "ECB mode...\n";
            ECB_Mode<AES>::Encryption ec;
            ec.SetKey(this->key, this->key_size);
            StringSource s(plain_text, true, 
			    new StreamTransformationFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }
        else if (mode == 2){
            wcout << "CBC mode...\n";
            CBC_Mode<AES>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(plain_text, true, 
			    new StreamTransformationFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }
        else if (mode == 3){
            wcout << "OFB mode...\n";
            OFB_Mode<AES>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(plain_text, true, 
			    new StreamTransformationFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }
        else if (mode == 4){
            wcout << "CFB mode...\n";
            CFB_Mode<AES>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(plain_text, true, 
			    new StreamTransformationFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }
        else if (mode == 5){
            wcout << "CTR mode...\n";
            CTR_Mode<AES>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(plain_text, true, 
			    new StreamTransformationFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }
        else if (mode == 6){
            wcout << "XTS mode...\n";
            XTS_Mode<AES>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(plain_text, true, 
			    new StreamTransformationFilter(ec,
				    new StringSink(cipher_text),
                    StreamTransformationFilter::NO_PADDING
			    )
		    );
        }
        else if (mode == 7){
            wcout << "CCM mode...\n";
            CCM<AES, TAG_SIZE>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            ec.SpecifyDataLengths( 0, plain_text.size(), 0 );
            StringSource s(plain_text, true, 
			    new AuthenticatedEncryptionFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }
        
        else {
            wcout << "GCM mode...\n";
            GCM<AES>::Encryption ec;
            ec.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(plain_text, true, 
			    new AuthenticatedEncryptionFilter(ec,
				    new StringSink(cipher_text)
			    )
		    );
        }

        

    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << '\n';
        exit(1);
    }
    
    return cipher_text;
}

string MyAES::Decryption(const string& cipher_text, const int mode){

    string plain_text;

    try
    {
        
        if (mode == 1){
            wcout << "ECB mode...\n";
            ECB_Mode<AES>::Decryption dc;
            dc.SetKey(this->key, this->key_size);
            StringSource s(cipher_text, true, 
			    new StreamTransformationFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }
        else if (mode == 2){
            wcout << "CBC mode...\n";
            CBC_Mode<AES>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(cipher_text, true, 
			    new StreamTransformationFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }
        else if (mode == 3){
            wcout << "OFB mode...\n";
            OFB_Mode<AES>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(cipher_text, true, 
			    new StreamTransformationFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }
        else if (mode == 4){
            wcout << "CFB mode...\n";
            CFB_Mode<AES>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(cipher_text, true, 
			    new StreamTransformationFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }
        else if (mode == 5){
            wcout << "CTR mode...\n";
            CTR_Mode<AES>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(cipher_text, true, 
			    new StreamTransformationFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }
        else if (mode == 6){
            wcout << "XTS mode...\n";
            XTS_Mode<AES>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(cipher_text, true, 
			    new StreamTransformationFilter(dc,
				    new StringSink(plain_text),
                    StreamTransformationFilter::NO_PADDING
			    )
		    );
        }
        else if (mode == 7){
            wcout << "CCM mode...\n";
            CCM<AES, TAG_SIZE>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            dc.SpecifyDataLengths( 0, cipher_text.size()-TAG_SIZE, 0 );
            StringSource s(cipher_text, true, 
			    new AuthenticatedDecryptionFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }
        
        else {
            wcout << "GCM mode...\n";
            GCM<AES>::Decryption dc;
            dc.SetKeyWithIV(this->key, this->key_size, iv);
            StringSource s(cipher_text, true, 
			    new AuthenticatedDecryptionFilter(dc,
				    new StringSink(plain_text)
			    )
		    );
        }

        

    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << '\n';
        exit(1);
    }

    return plain_text;
}

string MyAES::ByteToString(byte* value, const int size){
    string encoded;
    encoded.clear();
	StringSource(value, size, true,
		new HexEncoder(
			new StringSink(encoded)
		)
	);
    return encoded;
    
}

string MyAES::StringEncoded(const string& value){
    string encoded;
    StringSource(value, true,
		new HexEncoder(
			new StringSink(encoded)
		)
	);
    return encoded;
}

string MyAES::StringDecoded(const string& value){
    string decoded;
    StringSource(value, true,
		new HexDecoder(
			new StringSink(decoded)
		)
	);
    return decoded;
}