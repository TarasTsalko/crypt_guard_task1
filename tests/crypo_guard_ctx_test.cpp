#include <gtest/gtest.h>
#include <iostream>
#include <string>

#include "crypto_guard_ctx.h"

TEST(TestCryptoGuardCtx, BadInputDataStreamEncryptFileTest) {
    std::stringstream inputStream, outputStream;
    const std::string password = "123";
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    std::ios_base::iostate state = std::ios_base::iostate::_S_badbit;
    inputStream.setstate(state);
    EXPECT_THROW(
        {
            try {
                cryptoGuardCtx.EncryptFile(inputStream, outputStream, password);
            } catch (const std::ios_base::failure &e) {
                EXPECT_STREQ("Invalide input streams: iostream error", e.what());
                throw;
            }
        },
        std::ios_base::failure);
}

TEST(TestCryptoGuardCtx, BadOutputDataStreamEncryptFileTest) {
    std::stringstream inputStream, outputStream;
    const std::string password = "123";
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    std::ios_base::iostate state = std::ios_base::iostate::_S_badbit;
    outputStream.setstate(state);
    EXPECT_THROW(
        {
            try {
                cryptoGuardCtx.EncryptFile(inputStream, outputStream, password);
            } catch (const std::ios_base::failure &e) {
                EXPECT_STREQ("Invalide input streams: iostream error", e.what());
                throw;
            }
        },
        std::ios_base::failure);
}

TEST(TestCryptoGuardCtx, EncryptFileTest) {
    std::stringstream inputStream, encryptedStream, decryptedStream;
    const std::string password = "123";
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    const std::string inputData = "Life is like a Box of Chocolates";
    inputStream << inputData;
    cryptoGuardCtx.EncryptFile(inputStream, encryptedStream, password);
    cryptoGuardCtx.DecryptFile(encryptedStream, decryptedStream, password);
    EXPECT_STREQ(decryptedStream.str().c_str(), inputData.data());
}

TEST(TestCryptoGuardCtx, BadInputDataStreamDecryptFileTest) {
    std::stringstream inputStream, outputStream;
    const std::string password = "123";
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    std::ios_base::iostate state = std::ios_base::iostate::_S_badbit;
    inputStream.setstate(state);
    EXPECT_THROW(
        {
            try {
                cryptoGuardCtx.DecryptFile(inputStream, outputStream, password);
            } catch (const std::ios_base::failure &e) {
                EXPECT_STREQ("Invalide input streams: iostream error", e.what());
                throw;
            }
        },
        std::ios_base::failure);
}

TEST(TestCryptoGuardCtx, BadOutputDataStreamDecryptFileTest) {
    std::stringstream inputStream, outputStream;
    const std::string password = "123";
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    std::ios_base::iostate state = std::ios_base::iostate::_S_badbit;
    outputStream.setstate(state);
    EXPECT_THROW(
        {
            try {
                cryptoGuardCtx.DecryptFile(inputStream, outputStream, password);
            } catch (const std::ios_base::failure &e) {
                EXPECT_STREQ("Invalide input streams: iostream error", e.what());
                throw;
            }
        },
        std::ios_base::failure);
}

TEST(TestCryptoGuardCtx, DecryptFileTest) {
    std::stringstream inputStream, encryptedStream, decryptedStream;
    const std::string password = "abcd";
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    const std::string inputData = "Hello World!";
    inputStream << inputData;
    cryptoGuardCtx.EncryptFile(inputStream, encryptedStream, password);
    cryptoGuardCtx.DecryptFile(encryptedStream, decryptedStream, password);
    EXPECT_STREQ(decryptedStream.str().c_str(), inputData.data());
}

TEST(TestCryptoGuardCtx, CheckSumTest) {
    std::stringstream inputStream;
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    const std::string inputData = "Hello World!";
    inputStream << inputData;
    const std::string res = cryptoGuardCtx.CalculateChecksum(inputStream);
    const std::string etalonVal = "729e344a01e52c822bdfdec61e28d6eda02658d2e7d2b80a9b9029f41e212dde";
    EXPECT_STREQ(etalonVal.c_str(), res.c_str());
}

TEST(TestCryptoGuardCtx, BadInputSteamCheckSumTest) {
    std::stringstream inputStream;
    CryptoGuard::CryptoGuardCtx cryptoGuardCtx;
    const std::string inputData = "Hello World!";
    inputStream << inputData;
    std::ios_base::iostate state = std::ios_base::iostate::_S_badbit;
    inputStream.setstate(state);
    EXPECT_THROW(
        {
            try {
                const std::string res = cryptoGuardCtx.CalculateChecksum(inputStream);
            } catch (const std::ios_base::failure &e) {
                EXPECT_STREQ("Invalide input streams: iostream error", e.what());
                throw;
            }
        },
        std::ios_base::failure);
}
