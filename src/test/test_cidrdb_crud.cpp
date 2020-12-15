#include <boost/filesystem.hpp>
#include "gtest/gtest.h"
#include "cidr_db.hpp"

namespace fs = boost::filesystem;


class CidrDbTest : public ::testing::Test
{
protected:
    fs::path dbfilename;

    CidrDbTest()
    {
        dbfilename = fs::path("/tmp/cidr.db");
    }

    virtual ~CidrDbTest() { }

    virtual void TearDown()
    {
        if (fs::exists(dbfilename))
        {
            fs::remove(dbfilename);
        }
    }
};

TEST_F(CidrDbTest, MethodCommit)
{
    cidr::db db(dbfilename);
    EXPECT_NO_THROW(db.commit());
}

TEST_F(CidrDbTest, MethodHas)
{
    cidr::db db(dbfilename);
    EXPECT_FALSE(db.has("85.143.160.0/21"));
}

TEST_F(CidrDbTest, MethodHasPutHas)
{
    cidr::db db(dbfilename);
    EXPECT_FALSE(db.has("85.143.160.0/21"));
    db.put("85.143.160.0/21");
    EXPECT_TRUE(db.has("85.143.160.0/21"));
}

TEST_F(CidrDbTest, MethodPutHasDelHas)
{
    cidr::db db(dbfilename);
    db.put("85.143.160.0/21");
    EXPECT_TRUE(db.has("85.143.160.0/21"));
    db.del("85.143.160.0/21");
    EXPECT_FALSE(db.has("85.143.160.0/21"));
}

TEST_F(CidrDbTest, MethodPutCommitHas)
{
    cidr::db db(dbfilename);
    db.put("85.143.160.0/21");
    EXPECT_TRUE(db.has("85.143.160.0/21"));
    db.commit();
    cidr::db db2(dbfilename);
    EXPECT_TRUE(db2.has("85.143.160.0/21"));
}

TEST_F(CidrDbTest, MethodPutLookup)
{
    cidr::db db(dbfilename);
    db.put("85.143.160.0/21");
    EXPECT_TRUE(db.has("85.143.160.0/21"));
    std::vector<std::string> results;
    db.lookup("85.143.160.10", results);
    EXPECT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0], "85.143.160.0/21");
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
