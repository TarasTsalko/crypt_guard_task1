#include "crypto_guard_ctx.h"

#include <cassert>
#include <memory>
#include <openssl/evp.h>

// TODO:
#include <print>

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
        //
        // OpenSSL пример использования:
        //
        std::string input = "01234567890123456789";

        OpenSSL_add_all_algorithms();
        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        ctx_ = EVP_CIPHER_CTX_new();

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx_, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        // Обрабатываем первые N символов
        EVP_CipherUpdate(ctx_, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Обрабатываем оставшиеся символы
        EVP_CipherUpdate(ctx_, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx_, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
    }

    ~PImpl() {
        EVP_CIPHER_CTX_free(ctx_);
        std::print("String encoded successfully. Result: '{}'\n\n", output);
        EVP_cleanup();
        //
        // Конец примера
        //
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) { return; };

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) { return; };

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

private:
    EVP_CIPHER_CTX *ctx_;

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
    // pImpl_->DecryptFile( inStream, outStream, password );
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    assert(pImpl_);
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
