#include <gtest/gtest.h>
#include <string>

#include "cmd_options.h"

TEST(ProgramOptions, ParseTest_EmptyArgsTest) {
    char *args[] = {};
    const int argc = 0;

    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
    const std::string etalon("");
    EXPECT_EQ(options.GetInputFile(), etalon);
    EXPECT_EQ(options.GetOutputFile(), etalon);
    EXPECT_EQ(options.GetPassword(), etalon);
}

TEST(ProgramOptions, ParseTest_CommandNotSpecified) {
    char *args[] = {"CryptGuard", "-i", "input.txt", "-o", "output.txt", "-p", "123"};
    const int argc = 7;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
}

TEST(ProgramOptions, ParseTest_CommandNotSupported) {
    char *args[] = {"CryptGuard", "-i",         "input.txt", "--command", "encrypt_2",
                    "-o",         "output.txt", "-p",        "123",       nullptr};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
}

TEST(ProgramOptions, ParseTest_InputFileNotSpecified) {
    char *args[] = {"CryptGuard", "-i", "", "--command", "encrypt", "-o", "output.txt", "-p", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
    const std::string etalon("");
    EXPECT_EQ(options.GetInputFile(), etalon);
}

TEST(ProgramOptions, ParseTest_OutputFileNotSpecified) {
    char *args[] = {"CryptGuard", "-i", "input2.txt", "--command", "encrypt", "-o", "", "-p", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
    const std::string etalon("");
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_NE(options.GetInputFile(), etalon);
    EXPECT_EQ(options.GetOutputFile(), etalon);
}

TEST(ProgramOptions, ParseTest_PasswordNotSpecified) {
    char *args[] = {"CryptGuard", "-i", "input.txt", "--command", "encrypt", "-o", "output.txt", "-p", ""};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
    const std::string etalon("");
    EXPECT_EQ(options.GetPassword(), etalon);
}

TEST(ProgramOptions, ParseTest_IncorrectMode) {
    char *args[] = {"CryptGuard", "-i", "input.txt", "-o", "output.txt", "--command", "checksum", "-p", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_FALSE(res);
    const std::string etalon("");
    EXPECT_NE(options.GetPassword(), etalon);
    EXPECT_NE(options.GetOutputFile(), etalon);
}

TEST(ProgramOptions, ParseTest_IncryptCallShortFormat) {
    char *args[] = {"CryptGuard", "-i", "input.txt", "-o", "output.txt", "--command", "encrypt", "-p", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
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
    char *args[] = {"CryptGuard", "-i", "input.txt", "-o", "output.txt", "--command", "decrypt", "-p", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
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
    char *args[] = {"CryptGuard", "-i", "input.txt", "--command", "checksum"};
    const int argc = 5;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ParseTest_IncryptCallFullFormat) {
    char *args[] = {"CryptGuard", "--input", "input.txt",  "--output", "output.txt",
                    "--command",  "encrypt", "--password", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
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
    char *args[] = {"CryptGuard", "--input", "input.txt",  "--output", "output.txt",
                    "--command",  "decrypt", "--password", "123"};
    const int argc = 9;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
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
    char *args[] = {"CryptGuard", "--input", "input.txt", "--command", "checksum"};
    const int argc = 5;
    CryptoGuard::ProgramOptions options;
    const bool res = options.Parse(argc, args);
    EXPECT_TRUE(res);

    const std::string inputFile = "input.txt";
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}