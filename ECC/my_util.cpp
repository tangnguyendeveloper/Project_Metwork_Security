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

string string_to_hex(const string& input)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
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

void ShowMenu(){
    cout << "1. Signing\n";
    cout << "2. Verify\n";
    cout << "Select 1 in 2: ";
}