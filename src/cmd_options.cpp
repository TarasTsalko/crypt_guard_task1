#include "cmd_options.h"

#include <boost/program_options/errors.hpp>
#include <boost/program_options/parsers.hpp>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help, h", "produce help message")("input,i", po::value<std::string>(), "input file")(
        "command", po::value<std::string>(),
        "encrypt, decrypt, checksum")("output,o", po::value<std::string>(),
                                      "output file")("password,p", po::value<std::string>(), "password for encrypt");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {

    if (argc < 2)
        throw std::runtime_error("Args error: an empty set of arguments was passed.");

    po::variables_map vm;
    po::positional_options_description p;
    p.add("command", 1);
    try {
        auto parced_params = po::command_line_parser(argc, argv).options(desc_).run();
        po::store(parced_params, vm);
        po::notify(vm);
    } catch (po::error &e) {
        throw std::runtime_error(e.what());
        return false;
    }

    if (vm.count("help")) {
        std::cout << desc_;
        return false;  // Так как после вывода справки не нужно совершать действий (возможно для функции подошелбы enum)
    }

    if (vm.count("command")) {
        std::string argCommand = vm["command"].as<std::string>();
        const auto it = commandMapping_.find(argCommand);
        if (it == commandMapping_.end()) {
            const std::string message = std::string("Args error:command not supported ") + argCommand;
            throw std::runtime_error(message);
        }
        this->command_ = it->second;
    } else {
        throw std::runtime_error("Args error:'command' not specified");
    }

    if (vm.count("input"))
        inputFile_ = vm["input"].as<std::string>();

    if (vm.count("output"))
        outputFile_ = vm["output"].as<std::string>();

    if (inputFile_ == outputFile_)
        throw std::runtime_error("Args error:the input file and output file are the same");

    if (vm.count("password"))
        password_ = vm["password"].as<std::string>();

    if (inputFile_.empty())
        throw std::runtime_error("Args error:input file not specified");

    if (command_ != COMMAND_TYPE::CHECKSUM) {
        if (outputFile_.empty()) {
            throw std::runtime_error("Args error:output file not specified");
        }
        if (password_.empty())
            throw std::runtime_error("Args error:password not specified");

    } else {
        if (!outputFile_.empty() || !password_.empty()) {
            throw std::runtime_error("Args error:command checksum cannot be used with args password and output");
            return false;
        }
    }

    return true;
}

}  // namespace CryptoGuard
