#include "rsa_encrypt_decrypt.hpp"


void Setup(int& opt, int& input_opt);
void Run();

int main(int argc, char* argv[]){

    /*Set mode support Vietnamese*/
    #ifdef __linux__
        setlocale(LC_ALL,"");
    #elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif

    Run();
    
    return 0;
}

void Setup(int& opt, int& input_opt){
    ShowMenu();
    wcin >> opt;
    if (opt == 1) wcout << "---Plaintext---\n";
    else if (opt == 2) wcout << "---Ciphertext---\n";
    else assert(false);
    ShowOption();
    wcin >> input_opt;
}

void Run(){
    MyRSA rsa;

    int opt = 1, input_opt = 1;
    wstring filename, wplain, wcipher, plaintfile, cipherfile;
    string cipher, recovered;
    Setup(opt, input_opt);
    
    switch (opt)
    {
    case 1:
        wcout << "enter filrname public key: ";
        wcin >> filename;
        rsa.LoadPublicKey(wstring_utf8_to_string(filename).c_str());
        
        if (input_opt == 1){
            wcout << "Enter plaintext: ";
            wcin.ignore(2);
            getline(wcin, wplain);
        }
        else if (input_opt == 2){
            wcout << "enter plaintext filename: ";
            wcin >> plaintfile;
            wplain = LoadPlaintext(wstring_utf8_to_string(plaintfile).c_str());
        }
        else assert(false);

        cipher = rsa.Encyption(wstring_utf16_to_string(wplain));
        cipher = rsa.StringEncoded(cipher);
        wcout << "ciphertext: " << string_to_wstring_utf8(cipher) << endl;
        break;

    case 2:
        wcout << "enter filrname private key: ";
        wcin >> filename;
        rsa.LoadPrivateKey(wstring_utf8_to_string(filename).c_str());

        if (input_opt == 1){
            wcout << "Enter ciphertext: ";
            wcin.ignore(2);
            getline(wcin, wcipher);
        }
        else if (input_opt == 2){
            wcout << "enter ciphertext filename: ";
            wcin >> cipherfile;
            wcipher = LoadCiphertext(wstring_utf8_to_string(cipherfile).c_str());
        }
        else assert(false);

        cipher = wstring_utf8_to_string(wcipher);
        cipher = rsa.StringDecoded(cipher);
        recovered = rsa.Decryption(cipher);

        if (input_opt == 1) wcout << "plaintext: " << string_to_wstring_utf16(recovered) << endl;
        else SavePlaintextToFile("output.txt", string_to_wstring_utf16(recovered));
        break;
    
    default:
        break;
    }


}