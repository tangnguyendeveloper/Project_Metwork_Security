#include "my_util.hpp"
#include <iostream>
using namespace std;

/* convert string to wstring */
wstring string_to_wstring_utf8 (const string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

wstring string_to_wstring_utf16 (const string& str){
	wstring_convert<codecvt_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

/* convert wstring to string */

string wstring_utf8_to_string (const wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(str);
}

string wstring_utf16_to_string (const wstring& str)
{
    wstring_convert<codecvt_utf16<wchar_t>> converter;
    return converter.to_bytes(str);
}

string hex_to_string(const string& hex){
    string ascii = "";
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        string part = hex.substr(i, 2);
        char ch = stoul(part, nullptr, 16);
        ascii += ch;
    }
    return ascii;
}

wstring LoadPlaintext(const char* filename){
    wstring plaintext;
    wstring line;
    wifstream readfile(filename);
    plaintext.clear();
    while(readfile.good()){
        getline(readfile, line);
        plaintext = plaintext + line;
    }
    return plaintext;
}

wstring LoadCiphertext(const char* filename){
    wstring ciphertext;
    wifstream readfile(filename, ios::out);
    readfile >> ciphertext;
    return ciphertext;
}

void SavePlaintextToFile(const char* filename, wstring data){
    wofstream wofs(filename, wios::out);
    wofs << data;
    wofs.close();
}

void SaveCiphertextToFile(const char* filename, wstring data){
    wofstream ofs(filename, ios::out);
    ofs << data;
    ofs.close();
}

void ShowListMode() {
    wcout << "LIST AES MODE\n";
    wcout << "1. ECB\n";
    wcout << "2. CBC\n";
    wcout << "3. OFB\n";
    wcout << "4. CFB\n";
    wcout << "5. CTR\n";
    wcout << "6. XTS\n";
    wcout << "7. CCM\n";
    wcout << "8. GCM\n";
    wcout << "Select a mode: ";
}

void ShowInputOption() {
    wcout << "1. Input from screen\n";
    wcout << "2. Load from the file text\n";
    wcout << "Select 1 in 2: ";
}

void ShowKeyAndIVOption(){
    wcout << "1. Secret key and IV are randomly\n";
    wcout << "2. Input Secret Key and IV from screen\n";
    wcout << "3. Input Secret Key and IV from file\n";
    wcout << "Select 1 in 3: ";
}