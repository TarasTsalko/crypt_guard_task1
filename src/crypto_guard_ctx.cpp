#include "crypto_guard_ctx.h"

#include <cassert>
#include <memory>
#include <openssl/evp.h>

#include<iostream>
#include <vector>


namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::PImpl {
public:
    PImpl() {
        OpenSSL_add_all_algorithms();
    }

    ~PImpl() {
        EVP_cleanup();
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
    {
        IncryptDecryptImpl( inStream, outStream, password, 1 );
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
    {
        IncryptDecryptImpl( inStream, outStream, password, 0 );
    };

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void IncryptDecryptImpl( std::iostream &inStream, std::iostream &outStream, std::string_view password, int mode )
    {
        if ( !inStream.good() || !outStream.good() )
        {
            throw std::ios_base::failure( "Invalide input streams" );
        }
        auto deleter = [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(deleter)> ctx( EVP_CIPHER_CTX_new() );

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = mode;
        // Инициализируем cipher
        if (!EVP_CipherInit_ex( ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt ) )
            throw std::runtime_error( "Openssl init error" );

        unsigned int BLOCK_SIZE = 16;
        std::vector<unsigned char> inBuf( BLOCK_SIZE ), outBuf( BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH );
        int outLen = 0, part = 0;
        while( inStream.good() )
        {
            part = 0;
            for (int i = 0; i < BLOCK_SIZE; ++i ){
                const unsigned char ch =  static_cast<unsigned char>(inStream.get());
                if ( !inStream.good() ) break;
                inBuf[ i ] = ch;
                part++;
            }
            if ( !EVP_CipherUpdate( ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(part) ) )
                throw std::ios_base::failure( "encrypting/decrypting error" );

            for (int i = 0; i < outLen; ++i) {
                outStream.put(outBuf[i]);
            }

            if (inStream.bad() || outStream.bad())
                throw std::ios_base::failure( "encrypting/decrypting error" );
            outBuf.clear();
        }

        if( !EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) )
            throw std::ios_base::failure( "finilize encrypting/decrypting error" );

        for (int i = 0; i < outLen; ++i) {
            outStream.put(outBuf[i]);
        }
    }

private:
    std::string output;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<CryptoGuardCtx::PImpl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    assert(pImpl_);
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    assert(pImpl_);
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    assert(pImpl_);
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
