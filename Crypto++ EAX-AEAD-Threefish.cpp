#pragma warning(disable : 4996)
#include "stdafx.h"

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "threefish.h"
using CryptoPP::Threefish1024;

#include "eax.h"
using CryptoPP::EAX;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

#include <assert.h>

#define BUFFERSIZE 90
int main(int argc, char* argv[])
{

    typedef unsigned char byte;

    for (int i = 0; i < argc; i++)
        cout << argv[i] << endl;

    //string plaintext="Encrypted data";
    //string ciphertext, recovered;
    if (argc != 3) {
        cout << "Usage: Threefish1024-eax.exe [-ed] file" << endl;
        return 1;
    }
    unsigned int mode = (strcmp(argv[1], "-e") == 0) ? 0 : 1;//-e:0 -d:1
    try {
        const char* fin = argv[2];
        int len = strlen(fin);

        char k_filename[BUFFERSIZE];
        memset(k_filename, 0, BUFFERSIZE);
        char iv_filename[BUFFERSIZE];
        memset(iv_filename, 0, BUFFERSIZE);
        char ct[BUFFERSIZE];
        memset(ct, 0, BUFFERSIZE);
        char pt[BUFFERSIZE];
        memset(pt, 0, BUFFERSIZE);

        if (mode == 0) {
            strncpy(pt, fin, len);

            strncpy(ct, fin, len);
            strncat(ct, ".3fish.ct", 10);
        }
        else {
            strncpy(ct, fin, len);
            len -= 9;//plaintext_len
            strncpy(pt, fin, len);

        }

        strncpy(k_filename, pt, len);
        strncat(k_filename, ".3fish_key", 11);
        strncpy(iv_filename, pt, len);
        strncat(iv_filename, ".3fish_iv", 10);


        byte key[Threefish1024::BLOCKSIZE];
        memset(key, 0, sizeof(key));
        byte iv[Threefish1024::BLOCKSIZE];
        memset(iv, 0, sizeof(iv));

        if (mode == 0) {
            ////////////////////////////////////////////////
            // Generate keys
            AutoSeededRandomPool rng;

            rng.GenerateBlock(key, sizeof(key));
            StringSource(key, sizeof(key), true, new FileSink(k_filename));

            rng.GenerateBlock(iv, sizeof(iv));
            StringSource(iv, sizeof(iv), true, new FileSink(iv_filename));

            ////////////////////////////////////////////////
            // Encrpytion
            EAX< Threefish1024 >::Encryption enc;
            enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));


            FileSource(pt, true,
                new AuthenticatedEncryptionFilter(enc,
                    new FileSink(ct)
                )  // AuthenticatedEncryptionFilter
            ); // StringSource
        }


        ////////////////////////////////////////////////
        // Tamper
        // ciphertext[0] |= 0x0F;

        if (mode == 1) {
            ////////////////////////////////////////////////
            // Decrpytion
            FileSource(k_filename, true, new ArraySink(key, Threefish1024::BLOCKSIZE));
            FileSource(iv_filename, true, new ArraySink(iv, Threefish1024::BLOCKSIZE));

            EAX< Threefish1024 >::Decryption dec;
            dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

            FileSource(ct, true, new AuthenticatedDecryptionFilter(dec, new FileSink(pt)));

            //ArraySource( (byte*)ciphertext.data(), ciphertext.size(), true,
            //    new AuthenticatedDecryptionFilter( dec,
            //        new StringSink( recovered )
            //    ) // AuthenticatedDecryptionFilter

            //); //ArraySource

            //assert( plaintext == recovered );
            //cout << "Recovered original message" << endl;
        }

    } // try

    catch (CryptoPP::Exception& e)
    {
        std::cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
