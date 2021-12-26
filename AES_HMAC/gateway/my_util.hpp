#ifndef MY_UTIL_H_
#define MY_UTIL_H_

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <locale>
#include <codecvt>
#include <fstream>

using namespace std;


vector<string> StringSplit(string value, const string& delimiter);

/* convert string to wstring */
wstring string_to_wstring_utf8 (const string& str);
wstring string_to_wstring_utf16 (const string& str);

/* convert wstring to string */

string wstring_utf8_to_string (const wstring& str);
string wstring_utf16_to_string (const wstring& str);
string hex_to_string(const string& input);

wstring LoadPlaintext(const char* filename);
wstring LoadCiphertext(const char* filename);

void SavePlaintextToFile(const char* filename, wstring data);
void SaveCiphertextToFile(const char* filename, wstring data);

#endif /* MY_UTIL_H_ */