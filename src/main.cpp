#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;
        if (!options.Parse(argc, argv))
            return 1;

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inStream(options.GetInputFile(), std::ios::in);
            std::fstream outStream(options.GetOutputFile(), std::ios::out);
            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream inStream(options.GetInputFile(), std::ios::in);
            std::fstream outStream(options.GetOutputFile(), std::ios::out);
            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream inStream(options.GetInputFile(), std::ios::in);
            const std::string checksum = cryptoCtx.CalculateChecksum(inStream);
            std::print("Checksum: {}\n", checksum.c_str());
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}