#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include "cidr_db.hpp"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

int main(int ac, char** av)
{
    po::options_description desc("Parameters:");
    desc.add_options()
        ("in", po::value<std::string>(), "input source data filename")
        ("db", po::value<std::string>(), "CIDR database filename")
        ("ip", po::value<std::string>(), "IP address to scan");

    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
    po::notify(vm);

    if ( !vm.count("db") || !vm.count("ip") )
    {
        std::cerr << desc << std::endl;
        return 1;
    }

    fs::path infilename;
    fs::path dbfilename(vm["db"].as<std::string>());
    std::string ip_address(vm["ip"].as<std::string>());

    if (!fs::exists(dbfilename))
    {
        if (!vm["in"].empty())
            infilename = fs::path(vm["in"].as<std::string>());

        if (fs::exists(infilename))
        {
            cidr::db::build(infilename, dbfilename);
        }

        if (!fs::exists(dbfilename))
        {
            std::cerr << "Failed to read: " << infilename << std::endl;
            return 1;
        }
    }

    if (!cidr::db::valid_ip(ip_address))
    {
        std::cerr << "Invalid IP address: " << ip_address << std::endl;
        return 1;
    }

    cidr::db db(dbfilename);

    std::vector<std::string> results;

    db.lookup(ip_address, results);

    std::for_each(results.begin(), results.end(), [](std::string &cidr)
    {
        std::cout << cidr << std::endl;
    });

    return 0;
}
