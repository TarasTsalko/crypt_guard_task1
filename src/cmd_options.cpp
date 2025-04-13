#include "cmd_options.h"

#include <boost/program_options/errors.hpp>
#include <boost/program_options/parsers.hpp>
#include <iostream>
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

    // В функции используется std::cout вместо std::print, так как desc_ выводится в поток без дополнительный
    // действий в отличии std::print
    if (argc < 2) {
        std::cout << "Args error: an empty set of arguments was passed." << std::endl;
        return false;
    }

    po::variables_map vm;
    po::positional_options_description p;
    p.add("command", 1);
    try {
        auto parced_params = po::command_line_parser(argc, argv).options(desc_).run();
        po::store(parced_params, vm);
        po::notify(vm);
    } catch (po::error &e) {
        std::cout << e.what() << std::endl;
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
            std::cout << "Args error: Unsuprted commond: " << argCommand << std::endl;
            return false;
        }
        this->command_ = it->second;
    } else {
        std::cout << "Args:error: 'command' not specified" << std::endl;
        return false;
    }

    if (vm.count("input"))
        inputFile_ = vm["input"].as<std::string>();

    if (vm.count("output"))
        outputFile_ = vm["output"].as<std::string>();

    if (vm.count("password"))
        password_ = vm["password"].as<std::string>();

    if (inputFile_.empty()) {
        std::cout << "Args:error:input file not specified\n";
        return false;
    }
    if (command_ != COMMAND_TYPE::CHECKSUM) {
        if (outputFile_.empty()) {
            std::cout << "Args:error:output file not specified" << std::endl;
            return false;
        }
        if (password_.empty()) {
            std::cout << "Args:error:password not specified" << std::endl;
            return false;
        }
    } else {
        if (!outputFile_.empty() || !password_.empty()) {
            std::cout << "Args:error:incorrect mode" << std::endl;
            return false;
        }
    }

    return true;
}

}  // namespace CryptoGuard
