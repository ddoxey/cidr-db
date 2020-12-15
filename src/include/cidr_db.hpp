#ifndef CIDR_SCANNER_H
#define CIDR_SCANNER_H

#include <arpa/inet.h>
#include <set>
#include <map>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace cidr
{
    class db
    {
    public:
        db(const db&) = delete;
        db& operator=(const db&) = delete;

        explicit db() { };
        explicit db(const fs::path &dbfilename);

        void lookup(const std::string &ip_address, std::vector<std::string> &results) const;

        void put(const std::string &cidr);
        void del(const std::string &cidr);
        bool has(const std::string &cidr) const;
        void commit() const;

        static void build(const fs::path &infilename, const fs::path &dbfilename);
        static bool valid_ip(const std::string &ip_address);

    private:
        fs::path db_filename;
        void read(const fs::path &dbfilename);
        static in_addr_t ip_to_addr_bits(const std::string &dotted_quad);
        static std::string addr_bits_to_ip(const in_addr_t addr_bits);

        std::shared_ptr<std::set<in_addr_t>> cidrs[32];
    };
}

#endif // CIDR_SCANNER_H
