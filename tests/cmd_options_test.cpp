#include <array>
#include <gtest/gtest.h>
#include <iostream>
#include <stdexcept>
#include <string>

#include "cmd_options.h"

TEST(ProgramOptions, ParseTest_EmptyArgsTest) {
    std::array<const char *, 0> args;

    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error: an empty set of arguments was passed.", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_CommandNotSpecified) {
    std::array<const char *, 7> args = {"CryptGuard", "-i", "input.txt", "-o", "output.txt", "-p", "123"};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error:'command' not specified", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_CommandNotSupported) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",         "input.txt", "--command", "encrypt_2",
                                        "-o",         "output.txt", "-p",        "123"};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error:command not supported encrypt_2", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_InputFileNotSpecified) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",         "",   "--command", "encrypt",
                                        "-o",         "output.txt", "-p", "123"};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                std::cout << "MSG = " << e.what() << std::endl;
                EXPECT_STREQ("Args error:input file not specified", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_OutputFileNotSpecified) {
    std::array<const char *, 9> args = {"CryptGuard", "-i", "input2.txt", "--command", "encrypt",
                                        "-o",         "",   "-p",         "123"};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error:output file not specified", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_PasswordNotSpecified) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",         "input.txt", "--command", "encrypt",
                                        "-o",         "output.txt", "-p",        ""};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error:password not specified", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_IncorrectMode) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",       "input.txt", "-o", "output.txt",
                                        "--command",  "checksum", "-p",        "123"};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error:command checksum cannot be used with args password and output", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ParseTest_IncryptCallShortFormat) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",      "input.txt", "-o", "output.txt",
                                        "--command",  "encrypt", "-p",        "123"};
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(args.size(), const_cast<char **>(args.data()));
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    const std::string outputFile = "output.txt";
    const std::string command = "encrypt";
    const std::string password = "123";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), outputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetPassword(), password);
}

TEST(ProgramOptions, ParseTest_DecryptCallShortFormat) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",      "input.txt", "-o", "output.txt",
                                        "--command",  "decrypt", "-p",        "123"};
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(args.size(), const_cast<char **>(args.data()));
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    const std::string outputFile = "output.txt";
    const std::string password = "123";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), outputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetPassword(), password);
}

TEST(ProgramOptions, ParseTest_ChecksumCallShortFormat) {
    std::array<const char *, 5> args = {"CryptGuard", "-i", "input.txt", "--command", "checksum"};
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(args.size(), const_cast<char **>(args.data()));
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ParseTest_IncryptCallFullFormat) {
    std::array<const char *, 9> args = {"CryptGuard", "--input", "input.txt",  "--output", "output.txt",
                                        "--command",  "encrypt", "--password", "123"};
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(args.size(), const_cast<char **>(args.data()));
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    const std::string outputFile = "output.txt";
    const std::string command = "encrypt";
    const std::string password = "123";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), outputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetPassword(), password);
}

TEST(ProgramOptions, ParseTest_DecryptCallFullFormat) {
    std::array<const char *, 9> args = {"CryptGuard", "--input", "input.txt",  "--output", "output.txt",
                                        "--command",  "decrypt", "--password", "123"};
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(args.size(), const_cast<char **>(args.data()));
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    const std::string outputFile = "output.txt";
    const std::string password = "123";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), outputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetPassword(), password);
}

TEST(ProgramOptions, ParseTest_ChecksumCallFullFormat) {
    std::array<const char *, 5> args = {"CryptGuard", "--input", "input.txt", "--command", "checksum"};
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(args.size(), const_cast<char **>(args.data()));
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ParseTest_InputOutputFilesAreTheSame) {
    std::array<const char *, 9> args = {"CryptGuard", "-i",        "input.txt", "--command", "encrypt",
                                        "-o",         "input.txt", "-p",        "123"};
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(
        {
            try {
                options.Parse(args.size(), const_cast<char **>(args.data()));
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Args error:the input file and output file are the same", e.what());
                throw;
            }
        },
        std::runtime_error);
}