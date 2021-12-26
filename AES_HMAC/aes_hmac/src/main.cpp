#include <Arduino.h>
#include <string.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA3.h>

String input_string = "", data = "";
bool receive_complete = false;

#define DATA_SIZE 136
#define HASH_SIZE 32
#define BLOCK_SIZE 136

struct TestVector
{
    const char *name;
    byte key[32];
    byte plaintext[16];
    byte ciphertext[16];
};

struct TestHashVector
{
    const char *name;
    uint8_t data[DATA_SIZE];
    uint8_t dataSize;
    uint8_t hash[HASH_SIZE];
};

static TestVector const testVectorAES256 = {
    .name        = "AES-256-ECB",
    .key         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    .plaintext   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .ciphertext  = {0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
                    0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89}
};

static TestHashVector testVectorSHA3_256_5 = {
    "SHA3-256",
    {0xB3, 0x2D, 0x95, 0xB0, 0xB9, 0xAA, 0xD2, 0xA8,
     0x81, 0x6D, 0xE6, 0xD0, 0x6D, 0x1F, 0x86, 0x00,
     0x85, 0x05, 0xBD, 0x8C, 0x14, 0x12, 0x4F, 0x6E,
     0x9A, 0x16, 0x3B, 0x5A, 0x2A, 0xDE, 0x55, 0xF8,
     0x35, 0xD0, 0xEC, 0x38, 0x80, 0xEF, 0x50, 0x70,
     0x0D, 0x3B, 0x25, 0xE4, 0x2C, 0xC0, 0xAF, 0x05,
     0x0C, 0xCD, 0x1B, 0xE5, 0xE5, 0x55, 0xB2, 0x30,
     0x87, 0xE0, 0x4D, 0x7B, 0xF9, 0x81, 0x36, 0x22,
     0x78, 0x0C, 0x73, 0x13, 0xA1, 0x95, 0x4F, 0x87,
     0x40, 0xB6, 0xEE, 0x2D, 0x3F, 0x71, 0xF7, 0x68,
     0xDD, 0x41, 0x7F, 0x52, 0x04, 0x82, 0xBD, 0x3A,
     0x08, 0xD4, 0xF2, 0x22, 0xB4, 0xEE, 0x9D, 0xBD,
     0x01, 0x54, 0x47, 0xB3, 0x35, 0x07, 0xDD, 0x50,
     0xF3, 0xAB, 0x42, 0x47, 0xC5, 0xDE, 0x9A, 0x8A,
     0xBD, 0x62, 0xA8, 0xDE, 0xCE, 0xA0, 0x1E, 0x3B,
     0x87, 0xC8, 0xB9, 0x27, 0xF5, 0xB0, 0x8B, 0xEB,
     0x37, 0x67, 0x4C, 0x6F, 0x8E, 0x38, 0x0C, 0x04},
    136,
    {0xDF, 0x67, 0x3F, 0x41, 0x05, 0x37, 0x9F, 0xF6, 
     0xB7, 0x55, 0xEE, 0xAB, 0x20, 0xCE, 0xB0, 0xDC,
     0x77, 0xB5, 0x28, 0x63, 0x64, 0xFE, 0x16, 0xC5,
     0x9C, 0xC8, 0xA9, 0x07, 0xAF, 0xF0, 0x77, 0x32}
};

AESSmall256 aes256;
SHA3_256 sha3_256;

byte buffer[16];

void testCipher(BlockCipher *cipher, const struct TestVector *test);
void PrintArray(uint_fast8_t* array, int size);
void testHash_N(Hash *hash, const struct TestHashVector *test, size_t inc);
void hashKey(Hash *hash, const uint8_t *key, size_t keyLen, uint8_t pad);
void testHMAC(Hash *hash, size_t keyLen);

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  input_string.reserve(10);

  Serial.println();
  unsigned long start = micros(), end = 0;
  testCipher(&aes256, &testVectorAES256);
  end = micros() - start;
  Serial.print(end);
  Serial.println(" micros");

  Serial.println();
  start = micros();
  testHash_N(&sha3_256, &testVectorSHA3_256_5, testVectorSHA3_256_5.dataSize);
  end = micros() - start;
  Serial.print(end);
  Serial.println(" micros");

  Serial.println();
  start = micros();
  testHMAC(&sha3_256, HASH_SIZE);
  end = micros() - start;
  Serial.print(end);
  Serial.println(" micros");

}

void loop() {
  // put your main code here, to run repeatedly:
  if (receive_complete){
    Serial.println(input_string);
    Serial.println("______________");
    input_string = "";
    receive_complete = false;
    Serial.write("node hello 12345\n");
  }
  
}

void serialEvent(){
  while (Serial.available())
  {
    char in_char = (char)Serial.read();
    input_string += in_char;
    if (in_char == '\n') receive_complete = true;
  }
}

void PrintArray(uint8_t* array, int size){
  for (int i = 0; i < size; i++)
    Serial.print(*(array + i), HEX);
}

void testCipher(BlockCipher *cipher, const struct TestVector *test)
{
    Serial.println(test->name);

    cipher->setKey(test->key, cipher->keySize());
    cipher->encryptBlock(buffer, test->plaintext);
    Serial.print("cipher: ");
    PrintArray(buffer, 16);
    
    if (memcmp(buffer, test->ciphertext, 16) == 0)
        Serial.println("\tPassed");
    else
        Serial.println("\tFailed");

    cipher->decryptBlock(buffer, test->ciphertext);
    Serial.print("plaint: ");
    PrintArray(buffer, 16);

    if (memcmp(buffer, test->plaintext, 16) == 0)
        Serial.println("\tPassed");
    else
        Serial.println("\tFailed");
    
}
void testHash_N(Hash *hash, const struct TestHashVector *test, size_t inc)
{
    size_t size = test->dataSize;
    size_t posn, len;
    uint8_t value[HASH_SIZE];

    Serial.println(test->name);

    hash->reset();
    for (posn = 0; posn < size; posn += inc) {
        len = size - posn;
        if (len > inc)
            len = inc;
        hash->update(test->data + posn, len);
    }

    hash->finalize(value, sizeof(value));

    PrintArray(value, HASH_SIZE);

    if (memcmp(value, test->hash, sizeof(value)) != 0)
        Serial.println("\tFailed");
    else
        Serial.println("\tPassed");
}

void hashKey(Hash *hash, const uint8_t *key, size_t keyLen, uint8_t pad)
{
    size_t posn;
    uint8_t buf;
    uint8_t result[HASH_SIZE];
    if (keyLen <= BLOCK_SIZE) {
        hash->reset();
        for (posn = 0; posn < BLOCK_SIZE; ++posn) {
            if (posn < keyLen)
                buf = key[posn] ^ pad;
            else
                buf = pad;
            hash->update(&buf, 1);
        }
    } else {
        hash->reset();
        hash->update(key, keyLen);
        hash->finalize(result, HASH_SIZE);
        hash->reset();
        for (posn = 0; posn < BLOCK_SIZE; ++posn) {
            if (posn < HASH_SIZE)
                buf = result[posn] ^ pad;
            else
                buf = pad;
            hash->update(&buf, 1);
        }
    }

    
}

void testHMAC(Hash *hash, size_t keyLen)
{
    uint8_t result[HASH_SIZE];
    // Reuse one of the test vectors as a large temporary buffer.
    uint8_t *buffer = (uint8_t *)&testVectorSHA3_256_5;

    Serial.print("HMAC-SHA3-256 keysize=");
    Serial.print(keyLen);
    Serial.print(" ... ");

    // Construct the expected result with a simple HMAC implementation.
    memset(buffer, (uint8_t)keyLen, keyLen);
    hashKey(hash, buffer, keyLen, 0x36);
    memset(buffer, 0xBA, sizeof(testVectorSHA3_256_5));
    hash->update(buffer, sizeof(testVectorSHA3_256_5));
    hash->finalize(result, HASH_SIZE);
    memset(buffer, (uint8_t)keyLen, keyLen);
    hashKey(hash, buffer, keyLen, 0x5C);
    hash->update(result, HASH_SIZE);
    hash->finalize(result, HASH_SIZE);

    // Now use the library to compute the HMAC.
    hash->resetHMAC(buffer, keyLen);
    memset(buffer, 0xBA, sizeof(testVectorSHA3_256_5));
    hash->update(buffer, sizeof(testVectorSHA3_256_5));
    memset(buffer, (uint8_t)keyLen, keyLen);
    hash->finalizeHMAC(buffer, keyLen, buffer, HASH_SIZE);

    // Check the result.
    if (!memcmp(result, buffer, HASH_SIZE))
        Serial.println("Passed");
    else
        Serial.println("Failed");
    PrintArray(result, HASH_SIZE);
    Serial.println();
}