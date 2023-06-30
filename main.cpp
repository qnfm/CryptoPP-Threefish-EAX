#include <iostream>
#include <cstring>
#include <cstdlib>

#include <cryptopp/cryptlib.h>
#include <cryptopp/threefish.h>
#include <cryptopp/eax.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

using namespace std;
using namespace CryptoPP;

#define BUFFERSIZE 90

int main(int argc, char* argv[])
{

    for (int i = 0; i < argc; i++)
        cout << argv[i] << " ";
    cout << endl;

    if (argc != 3) {
        cout << "Usage: Threefish1024-eax [-ed] file" << endl;
        return 1;
    }

    // -e: 0 (Encrypt), -d: 1 (Decrypt)
    unsigned int mode = (strcmp(argv[1], "-e") == 0) ? 0 : 1;

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
            // Encryption Mode
            strncpy(pt, fin, BUFFERSIZE - 1);
            strncpy(ct, fin, BUFFERSIZE - 15); // Leave room for suffix
            strncat(ct, ".3fish.ct", 10);
        }
        else {
            // Decryption Mode
            strncpy(ct, fin, BUFFERSIZE - 1);
            // Simple logic to deduce original filename (unsafe for general use, strictly matches your logic)
            if(len > 9) len -= 9;
            strncpy(pt, fin, len);
            pt[len] = '\0'; // Ensure null termination
        }

        // Generate Key/IV filenames based on plaintext name
        strncpy(k_filename, pt, BUFFERSIZE - 15);
        strncat(k_filename, ".3fish_key", 11);
        strncpy(iv_filename, pt, BUFFERSIZE - 15);
        strncat(iv_filename, ".3fish_iv", 10);

        SecByteBlock key(Threefish1024::DEFAULT_KEYLENGTH);
        CryptoPP::byte iv[Threefish1024::BLOCKSIZE];

        memset(iv, 0, sizeof(iv));

        if (mode == 0) {
            ////////////////////////////////////////////////
            // Encryption

            AutoSeededRandomPool rng;

            // Generate and save Key
            rng.GenerateBlock(key, key.size());
            StringSource(key, key.size(), true, new FileSink(k_filename));

            // Generate and save IV
            rng.GenerateBlock(iv, sizeof(iv));
            StringSource(iv, sizeof(iv), true, new FileSink(iv_filename));

            EAX< Threefish1024 >::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

            // Encrypt file: Plaintext File -> Encrypt -> Ciphertext File
            FileSource(pt, true,
                new AuthenticatedEncryptionFilter(enc,
                    new FileSink(ct)
                )
            );

            cout << "Encrypted " << pt << " to " << ct << endl;
        }
        else if (mode == 1) {
            ////////////////////////////////////////////////
            // Decryption

            // Load Key and IV from files
            FileSource(k_filename, true, new ArraySink(key, key.size()));
            FileSource(iv_filename, true, new ArraySink(iv, sizeof(iv)));

            EAX< Threefish1024 >::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

            // Decrypt file: Ciphertext File -> Decrypt -> Plaintext File (restored)
            // Note: In your original logic 'pt' is the output filename for decryption
            FileSource(ct, true,
                new AuthenticatedDecryptionFilter(dec,
                    new FileSink(pt)
                )
            );

            cout << "Decrypted " << ct << " to " << pt << endl;
        }

    }
    catch (CryptoPP::Exception& e)
    {
        std::cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}
