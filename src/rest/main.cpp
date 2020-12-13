///
/// \file posix_main.cpp
///
/// POSIX (Linux/Unix/Cygwin) entry point with clean shutdown signal managment.
///
/// Copyright (c) 2003-2011 Christopher M. Kohlhoff (chris at kohlhoff dot com)
///
/// Distributed under the Boost Software License, Version 1.0. (See accompanying
/// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
///

#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include "server.hpp"
#include "cidr_db.hpp"

#include <pthread.h>
#include <signal.h>

namespace fs = boost::filesystem;

int main(int argc, char* argv[])
{
  try
  {
    // Check command line arguments.
    if (argc != 4)
    {
      std::cerr << "Usage: "
                << "cidrdb_rest <address> <port> <cidr-db-filename>"
                << std::endl;
      return 1;
    }

    // Block all signals for background thread.
    sigset_t new_mask;
    sigfillset(&new_mask);
    sigset_t old_mask;
    pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

    const std::string address(argv[1]);
    const std::string port(argv[2]);
    const fs::path cidr_dbfilename(argv[3]);

    if (!fs::exists(cidr_dbfilename))
    {
        std::cerr
            << "Can't open "
            << cidr_dbfilename
            << " (No such file)"
            << std::endl;
        return 1;
    }

    std::cerr << "loading cidr::db ... ";
    auto cidr_db = std::make_shared<cidr::db>(cidr_dbfilename);
    std::cerr << "OK" << std::endl;

    // Run server in background thread.
    http::server::server s(address, port, cidr_db);
    boost::thread t(boost::bind(&http::server::server::run, &s));

    // Restore previous signals.
    pthread_sigmask(SIG_SETMASK, &old_mask, 0);

    // Wait for signal indicating time to shut down.
    sigset_t wait_mask;
    sigemptyset(&wait_mask);
    sigaddset(&wait_mask, SIGINT);
    sigaddset(&wait_mask, SIGQUIT);
    sigaddset(&wait_mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &wait_mask, 0);
    int sig = 0;
    sigwait(&wait_mask, &sig);

    // Stop the server.
    s.stop();
    t.join();
  }
  catch (std::exception& e)
  {
    std::cerr << "exception: " << e.what() << "\n";
  }

  return 0;
}
