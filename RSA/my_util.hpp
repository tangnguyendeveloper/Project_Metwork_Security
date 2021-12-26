#ifndef MY_UTIL_H_
#define MY_UTIL_H_

#include <string>
#include <locale>
#include <codecvt>
#include <fstream>
#include <exception>
#include <assert.h>
#include <fcntl.h>

/* Set _setmode()*/ 
#ifdef _WIN32
    #include <io.h>
#elif __linux__
    #include <inttypes.h>
    #include <unistd.h>
    #define __int64 int64_t
    #define _close close
    #define _read read
    #define _lseek64 lseek64
    #define _O_RDONLY O_RDONLY
    #define _open open
    #define _lseeki64 lseek64
    #define _lseek lseek
    #define stricmp strcasecmp
#endif

using namespace std;


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

void ShowOption();
void ShowMenu();


#endif /* MY_UTIL_H_ */