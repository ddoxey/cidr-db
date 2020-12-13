#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include "cidr_db.hpp"

namespace ba = boost::algorithm;
namespace fs = boost::filesystem;


namespace cidr
{
    /**
     * Constructor for cidr::db.
     *
     * @param boost::filesystem::path indicates path to compiled CIDR datafile
     */
    db::db(const fs::path &db_filename)
    {
        read(db_filename);
    }

    /**
     * Method to lookup CIDR entries for a given IP address.
     *
     * @param std::string IP address
     * @param vector<string> to store CIDR results
     */
    void db::lookup(const std::string &ip_address, std::vector<std::string> &results)
    {
        const char* DEBUG = std::getenv("DEBUG");

        in_addr_t ip_bits = ip_to_addr_bits(ip_address);

        for (size_t offset = 1; offset <= 32; offset++)
        {
            if (cidrs[offset - 1] == 0)
                continue;

            in_addr_t shifted_bits = ip_bits >> offset;

            if (cidrs[offset - 1].get()->count(shifted_bits) == 0)
                continue;

            in_addr_t unshifted_bits = shifted_bits << offset;

            if (DEBUG)
            {
                std::cerr
                    << "found: "
                    << shifted_bits
                    << std::endl
                    << "["
                    << std::bitset<32>(unshifted_bits)
                    << "] <= ["
                    << std::bitset<32>(shifted_bits)
                    << "]"
                    << std::endl;
            }

            std::stringstream cidr;

            cidr << addr_bits_to_ip(unshifted_bits) << "/" << (32 - offset);

            results.push_back(cidr.str());
        }
    }

    /**
     * Method to read a CIDR database file to initialize the in-memory database.
     *
     * @param boost::filesystem::path indicates path to compiled CIDR datafile
     */
    void db::read(const fs::path &db_filename)
    {
        const char* DEBUG = std::getenv("DEBUG");

        std::ifstream infile(db_filename.c_str());

        size_t offset;
        in_addr_t shifted_bits;

        while (!infile.eof())
        {
            infile.read( (char*)&offset, sizeof(size_t) );
            infile.read( (char*)&shifted_bits, sizeof(in_addr_t) );

            if (shifted_bits == 0) continue;

            if (32 < offset || offset < 1) continue;

            if (DEBUG)
            {
                std::cerr
                    << shifted_bits
                    << "/"
                    << offset
                    << " [" << std::bitset<32>(shifted_bits) << "]"
                    << std::endl;
            }

            offset -= 1;

            if (cidrs[offset] == 0)
                cidrs[offset] = std::shared_ptr<std::set<in_addr_t>>(
                    new std::set<in_addr_t>
                );

            cidrs[offset].get()->insert(shifted_bits);
        }

        infile.close();
    }

    /**
     * Static fuction to create a compiled CIDR database file.
     *
     * @param boost::filesystem::path indicating path to raw CIDR datafile
     * @param boost::filesystem::path indicates path to compiled CIDR datafile
     */
    void db::build(const fs::path &infilename, const fs::path &db_filename)
    {
        const char* DEBUG = std::getenv("DEBUG");

        if (DEBUG)
            std::cerr << "Opening: " << infilename << std::endl;

        std::ifstream infile(infilename.c_str());
        std::ofstream dbfile(db_filename.c_str(), std::ios::out|std::ios::binary);

        std::string cidr;
        in_addr_t shifted_bits;
        in_addr_t cidr_bits;
        size_t offset;

        while (infile >> cidr)
        {
            std::vector<std::string> parts;
            ba::split(parts, cidr, boost::is_any_of("/"));

            cidr_bits = ip_to_addr_bits(parts[0]);
            offset = 32 - boost::lexical_cast<size_t>(parts[1].c_str());

            if (DEBUG)
            {
                std::cerr
                    << parts[0]
                    << " -> "
                    << "["
                    << std::bitset<32>(cidr_bits)
                    << "]"
                    << std::endl;
            }

            if (cidr_bits == 0) continue;

            if (32 < offset || offset < 1) continue;

            shifted_bits = cidr_bits >> offset;

            if (DEBUG)
            {
                std::cerr
                    << cidr
                    << " " << parts[1] << " => "
                    << offset
                    << ")"
                    << std::endl
                    << "["
                    << std::bitset<32>(cidr_bits)
                    << "] => ["
                    << std::bitset<32>(shifted_bits)
                    << "]"
                    << std::endl;
            }

            dbfile.write(reinterpret_cast<char*>( &offset ), sizeof offset);
            dbfile.write(reinterpret_cast<char*>( &shifted_bits ), sizeof shifted_bits);
        }

        dbfile.close();
        infile.close();
    }

    /**
     * Static function to validate a string as a legitimate IPv4 address.
     *
     * @param std::string representing an IP address
     * @return bool
     */
    bool db::valid_ip(const std::string &ip_address)
    {
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ip_address.c_str(), &(sa.sin_addr));
        return result != 0;
    }

    /**
     * Convert an IPv4 address to a host byte order int binary.
     *
     * @param std::string IPv4 address
     * @return in_addr_t in reversed binary order
     */
    in_addr_t db::ip_to_addr_bits(const std::string &ip_address)
    {
        return inet_network(ip_address.c_str());
    }

    /**
     * Convert a binary host byte order in_addr_t to an IPv4 string.
     *
     * @param in_addr_t in reverse binary
     * @retrun std::string IPv4
     */
    std::string db::addr_bits_to_ip(const in_addr_t addr_bits)
    {
        in_addr_t addr_stib = htonl(addr_bits);
        std::string ip_address(INET_ADDRSTRLEN, '\0');
        inet_ntop(AF_INET, &addr_stib, &ip_address[0], ip_address.size());
        ip_address.assign(ip_address.c_str()); // trim extra null chars
        return ip_address;
    }
}
