#include "my_ecdsa.hpp"

void Signing();
void Verify();

int main(int argc, char* argv[]){
    /*
    #ifdef __linux__
        setlocale(LC_ALL,"");
    #elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif
    */

    //bool result = false;   
    
    // Private and Public keys
    //ECDSA<ECP, SHA3_256>::PrivateKey privateKey;
    //ECDSA<ECP, SHA3_256>::PublicKey publicKey;
    
    /////////////////////////////////////////////
    // Generate Keys
   
    //result = GenerateKey( privateKey, publicKey );
    //assert( true == result );
    //if( !result ) { return -2; }
    
    /////////////////////////////////////////////
    // Save key in PKCS#9 and X.509 format    
    //SavePrivateKey( "ec.private.key", privateKey );
    //SavePublicKey( "ec.public.key", publicKey );
    
    /////////////////////////////////////////////
    // Load key in PKCS#9 and X.509 format     
    //LoadPrivateKey( "ec.private.key", privateKey );
    //LoadPublicKey( "ec.public.key", publicKey );

    /////////////////////////////////////////////
    // Print Domain Parameters and Keys    
    //PrintDomainParameters( publicKey );
    //PrintPrivateKey( privateKey );
    //PrintPublicKey( publicKey );
        
    /////////////////////////////////////////////
    // Sign and Verify a message      
    //string message = "Yoda said, Do or do not. There is no try.";
    //string signature;

    //result = SignMessage( privateKey, message, signature );
    //assert( true == result );

    //result = VerifyMessage( publicKey, message, signature );
    //assert( true == result );

    ShowMenu();
    unsigned int option = 0;
    cin >> option;

    switch (option)
    {
    case 1:
        Signing();
        break;
    
    case 2:
        Verify();
        break;

    default:
        break;
    }

    return 0;
}

void Signing(){
    ECDSA<ECP, SHA3_256>::PrivateKey privateKey;
    string file_mess, file_key, message, signature;

    cout << "emter filename of key: ";
    cin >> file_key;
    cout << "emter filename of message: ";
    cin >> file_mess;

    LoadPrivateKey( file_key, privateKey );
    PrintPrivateKey(privateKey);
    message = wstring_utf16_to_string(LoadPlaintext(file_mess.c_str()));
    bool result = SignMessage( privateKey, message, signature );
    assert( true == result );

    cout << "signature (r:s) : " << signature << endl;
}

void Verify(){
    ECDSA<ECP, SHA3_256>::PublicKey publicKey;
    string file_mess, file_key, message, signature;

    cout << "emter filename of key: ";
    cin >> file_key;
    cout << "emter filename of message: ";
    cin >> file_mess;
    cout << "enter signature (r:s) (12abh:34cdh): ";
    cin >> signature;

    LoadPublicKey( file_key, publicKey );
    PrintPublicKey(publicKey);
    message = wstring_utf16_to_string(LoadPlaintext(file_mess.c_str()));
    bool result = VerifyMessage( publicKey, message, signature );
    assert( true == result );

    cout << "Verify OK" << endl;
}