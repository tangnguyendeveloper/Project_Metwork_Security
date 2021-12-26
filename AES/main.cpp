#include <iostream>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#include "aes_encrypt_decrypt.hpp"

using namespace std;

void Setup(int& method, int& mode, int& key_and_iv);
void GetPlaintext(const int& method, wstring& wplaintext);
void SetKeyAndIV(MyAES& myaes, const int& mode, const int& key_and_iv);

int main(int argc, char* argv[]){
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    int mode = 1, method = 1, key_and_iv = 1;
    wstring wplaintext;
    string plaintext, ciphertext, recovered;
    MyAES myaes;
    
    Setup(method, mode, key_and_iv);
    GetPlaintext(method, wplaintext);
    SetKeyAndIV(myaes, mode, key_and_iv);
    
    plaintext = wstring_utf16_to_string(wplaintext);
    ciphertext = myaes.Encryption(plaintext, mode);
    //SaveCiphertextToFile("testcipher.txt", string_to_wstring_utf8(myaes.StringEncoded(ciphertext)));
    //mode = 2;
    //myaes.LoadKeyFromFile("AES_key_Random.key");
    //myaes.LoadIVFromFile("AES_IV_Random.iv");
    //myaes.SetKeyFromHexString("E9B4F7889DB7397C1C2016C14246DCC2F8AAA0D7AA6A0C59FCE4544357054C35");
    //myaes.SetIVFromHexString("628B5D4408B212D159E1210942050907");
    //wstring data = LoadCiphertext("testcipher.txt");
    //wcout << data << endl;
   // ciphertext = myaes.StringDecoded(wstring_utf8_to_string(data));
    recovered = myaes.Decryption(ciphertext, mode);

    wcout << "KEY: " << string_to_wstring_utf8(myaes.GetKey()) << endl;
    wcout << "IV: " << string_to_wstring_utf8(myaes.GetIV()) << endl;
    wcout << "Plain text: " << wplaintext << endl;
    wcout << "Cipher text: " << string_to_wstring_utf8(myaes.StringEncoded(ciphertext)) << endl;
    wcout << "Recovered: " << string_to_wstring_utf16(recovered) << endl;
    //wcout << "Recovered: " << string_to_wstring_utf8(recovered) << endl;
    //SavePlaintextToFile("newdata.txt", string_to_wstring_utf16(recovered));
    return 0;
}


void Setup(int& method, int& mode, int& key_and_iv){
    ShowListMode();
    wcin >> mode;
    ShowKeyAndIVOption();
    wcin >> key_and_iv;
    ShowInputOption();
    wcin >> method;
}

void GetPlaintext(const int& method, wstring& wplaintext){
    if (method == 1){
        wcout << "Enter plain text: ";
        wcin.ignore(2);
        getline(wcin, wplaintext);
    }
    else if (method == 2) {
        wstring filename;
        wcout << "Enter filename or part : ";
        wcin >> filename;
        wcin.ignore(2);
        wplaintext = LoadPlaintext(wstring_utf8_to_string(filename).c_str());
    }
}

void SetKeyAndIV(MyAES& myaes, const int& mode, const int& key_and_iv){
    wstring file_key, file_iv;
    switch (key_and_iv)
    {
    case 1:
        myaes.RandomKey();
        if (mode != 1) myaes.RandomIV();
        break;
    
    case 2:
        myaes.InputKey();
        if (mode != 1) myaes.InputIV();
        break;
    
    case 3:
        
        wcout << "Emter filename of key: ";
        wcin.ignore();
        getline(wcin, file_key);
        myaes.LoadKeyFromFile(wstring_utf8_to_string(file_key).c_str());
        if (mode != 1){
            wcout << "Emter filename of IV: ";
            wcin.ignore();
            getline(wcin, file_iv);
            myaes.LoadIVFromFile(wstring_utf8_to_string(file_iv).c_str());
        }
        break;
    
    default:
        break;
    }
}
