#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include "cidr_db.hpp"

namespace ba = boost::algorithm;
namespace fs = boost::filesystem;

const unsigned char BitReverseTable256[] = {
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};


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

            in_addr_t shifted_bits = ip_bits << offset;

            if (cidrs[offset - 1].get()->count(shifted_bits) == 0)
                continue;

            in_addr_t unshifted_bits = shifted_bits >>  offset;

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

            shifted_bits = cidr_bits << offset;

            if (DEBUG)
            {
                std::cerr
                    << cidr
                    << " (32 - " << parts[1] << " => "
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
     * Convert an IPv4 address to a host byte order int in reversed binary
     * order.
     *
     * @param std::string IPv4 address
     * @return in_addr_t in reversed binary order
     */
    in_addr_t db::ip_to_addr_bits(const std::string &ip_address)
    {
        in_addr_t addr_stib = inet_network(ip_address.c_str());
        in_addr_t addr_bits = (BitReverseTable256[addr_stib & 0xff] << 24) |
                              (BitReverseTable256[(addr_stib >> 8) & 0xff] << 16) |
                              (BitReverseTable256[(addr_stib >> 16) & 0xff] << 8) |
                              (BitReverseTable256[(addr_stib >> 24) & 0xff]);
        return addr_bits;
    }

    /**
     * Convert a reverse binary host byte order in_addr_t to an IPv4 string.
     *
     * @param in_addr_t in reverse binary
     * @retrun std::string IPv4
     */
    std::string db::addr_bits_to_ip(const in_addr_t addr_bits)
    {
        in_addr_t addr_stib = htonl((BitReverseTable256[addr_bits & 0xff] << 24) |
                                    (BitReverseTable256[(addr_bits >> 8) & 0xff] << 16) |
                                    (BitReverseTable256[(addr_bits >> 16) & 0xff] << 8) |
                                    (BitReverseTable256[(addr_bits >> 24) & 0xff]));
        std::string ip_address(INET_ADDRSTRLEN, '\0');
        inet_ntop(AF_INET, &addr_stib, &ip_address[0], ip_address.size());
        ip_address.assign(ip_address.c_str()); // trim extra null chars
        return ip_address;
    }
}
