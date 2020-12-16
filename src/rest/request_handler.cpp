/// REST Service Interface for CIDR-DB
///
/// Derived from:
///
/// \file request_handler.cpp
///
/// Handle a HTTP request by returning the client the resource he asked.
///
/// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
/// Copyright (c) 2012-2017 Sebastien Rombauts (sebastien.rombauts@gmail.com)
///
/// Distributed under the Boost Software License, Version 1.0. (See accompanying
/// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
///

#include "request_handler.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include "mime_types.hpp"
#include "reply.hpp"
#include "request.hpp"
#include "cidr_db.hpp"

namespace b = boost;
namespace ba = boost::algorithm;

namespace http {
namespace server {

/**
 * This request handler supports the following CIDR-DB operations:
 *
 *     GET     /           -- status
 *     POST    /           -- batch lookup
 *     GET     /<ip>       -- single lookup
 *     GET     /<ip>/<int> -- has (verify)
 *     PUT     /<ip>/<int> -- add/update
 *     DELETE  /<ip>/<int> -- delete
 */
std::string determine_op(const std::vector<std::string> &path_tokens,
                       const std::string &method)
{
    size_t token_count = std::count_if(path_tokens.begin(), path_tokens.end(),
        [](auto token) { return token != ""; });

    // path: /
    if (token_count == 0)
    {
        if (method == "GET")
            return "Status";  // get the CIDR-DB status

        if (method == "POST")
            return "Batch-Lookup";  // lookup CIDRs for multiple IPs
    }
    // path: /<ip>
    else if (token_count == 1)
    {
        if (method == "GET")
            return "Single-Lookup";  // lookup CIDRs for an IP
    }
    // path: /<ip>/<int>
    else if (token_count == 2)
    {
        if (method == "GET")
            return "Verify";  // verify CIDR present

        if (method == "PUT")
            return "Add";     // add a new CIDR

        if (method == "DELETE")
            return "Delete";  // delete a CIDR
    }

    return "Invalid";
}

request_handler::request_handler(std::shared_ptr<cidr::db> &cidr_db)
    : cidr_db_(cidr_db)
    { }

void request_handler::handle_request(const request &req, reply &rep)
{
    std::string request_path;
    std::string accept_type(mime_types::extension_to_type("json"));

    if (!url_decode(req.uri, request_path))
    {
        reply::stock_reply(reply::bad_request, rep);
        return;
    }

    auto accept_header = std::find_if(req.headers.begin(), req.headers.end(),
        [](auto &header) { return header.name == "Accept"; });

    if (accept_header != req.headers.end())
        accept_type = accept_header[0].value;

    if (   accept_type != mime_types::extension_to_type("json")
        && accept_type != mime_types::extension_to_type("yaml"))
    {
        rep.status = reply::bad_request;
        rep.content.append("Unsupported content type: ");
        rep.content.append(accept_type);
        rep.content.append("\n\n");
        rep.content.append("Supported types include:");
        rep.content.append("\n  - ");
        rep.content.append(mime_types::extension_to_type("json"));
        rep.content.append("\n  - ");
        rep.content.append(mime_types::extension_to_type("yaml"));
        rep.content.append("\n");
        rep.headers.resize(2);
        rep.headers[0].name = "Content-Length";
        rep.headers[0].value = std::to_string(rep.content.size());
        rep.headers[1].name = "Content-Type";
        rep.headers[1].value = mime_types::extension_to_type("txt");
        return;
    }

    std::vector<std::string> path_tokens;
    ba::split(path_tokens, request_path, b::is_any_of("/"));
    std::remove_if(path_tokens.begin(), path_tokens.end(),
        [](auto token) { return token == ""; });

    std::string op_type(determine_op(path_tokens, req.method));

    if (op_type == "Invalid")
    {
        reply::stock_reply(reply::not_found, rep);
        return;
    }
    else if (op_type == "Status")
    {
        if (accept_type == mime_types::extension_to_type("json"))
        {
            rep.content.append("{\"status\":\"OK\"}");
        }
        else if (accept_type == mime_types::extension_to_type("yaml"))
        {
            rep.content.append("---\n");
            rep.content.append("status: OK\n");
        }

        rep.content.append("\n");
        rep.headers.resize(3);
        rep.headers[0].name = "X-Operation";
        rep.headers[0].value = op_type;
        rep.headers[1].name = "Content-Length";
        rep.headers[1].value = std::to_string(rep.content.size());
        rep.headers[2].name = "Content-Type";
        rep.headers[2].value = accept_type;
        rep.status = reply::ok;
        return;
    }
    else if (op_type == "Batch-Lookup" || op_type == "Single-Lookup")
    {
        std::vector<std::string> lines;

        if (op_type == "Batch-Lookup")
        {
            std::string content;
            if (!url_decode(req.content, content))
            {
                reply::stock_reply(reply::bad_request, rep);
                return;
            }

            ba::split(lines, content, b::is_any_of("\r\n"));
        }
        else if (op_type == "Single-Lookup")
        {
            lines.push_back(path_tokens[0]);
        }

        if (lines.size() < 1)
        {
            reply::stock_reply(reply::bad_request, rep);
            return;
        }

        if (accept_type == mime_types::extension_to_type("json"))
        {
            rep.content.append("[");

            std::string comma1("");
            std::for_each(lines.begin(), lines.end(),
                [&comma1, &rep, this](std::string &ip)
                {
                    if (ip.empty()) return;

                    std::string valid("false");
                    std::vector<std::string> results;

                    if (cidr::db::valid_ip(ip))
                    {
                        valid = "true";
                        cidr_db_.get()->lookup(ip, results);
                    }

                    rep.content.append(comma1);
                    rep.content.append("{\"ip\":\"");
                    rep.content.append(ip);
                    rep.content.append("\",\"valid\":");
                    rep.content.append(valid);
                    rep.content.append(",\"cidrs\":[");

                    std::string comma2("");
                    std::for_each(results.begin(), results.end(),
                        [&comma2, &rep](std::string &cidr)
                        {
                            rep.content.append(comma2);
                            rep.content.append("\"");
                            rep.content.append(cidr);
                            rep.content.append("\"");
                            comma2 = ",";
                        }
                    );

                    rep.content.append("]}");
                    comma1 = ",";
                }
            );

            rep.content.append("]");
        }
        else if (accept_type == mime_types::extension_to_type("yaml"))
        {
            rep.content.append("---\n");

            std::for_each(lines.begin(), lines.end(),
                [&rep, this](std::string &ip)
                {
                    if (ip.empty()) return;

                    std::string valid("false");
                    std::vector<std::string> results;

                    if (cidr::db::valid_ip(ip))
                    {
                        valid = "true";
                        cidr_db_.get()->lookup(ip, results);
                    }

                    rep.content.append("-  ip: ");
                    rep.content.append(ip);
                    rep.content.append("\n");
                    rep.content.append("   valid: ");
                    rep.content.append(valid);
                    rep.content.append("\n");
                    rep.content.append("   cidrs:\n");

                    std::for_each(results.begin(), results.end(),
                        [&rep](std::string &cidr)
                        {
                            rep.content.append("   - ");
                            rep.content.append(cidr);
                            rep.content.append("\n");
                        }
                    );
                }
            );
        }

        rep.content.append("\n");
        rep.headers.resize(3);
        rep.headers[0].name = "X-Operation";
        rep.headers[0].value = op_type;
        rep.headers[1].name = "Content-Length";
        rep.headers[1].value = std::to_string(rep.content.size());
        rep.headers[2].name = "Content-Type";
        rep.headers[2].value = accept_type;
        rep.status = reply::ok;

        return;
    }
    else if (op_type == "Verify" || op_type == "Add" || op_type == "Delete")
    {
        std::string cidr(path_tokens[0]
                       + "/"
                       + path_tokens[1]);

        if (!cidr::db::valid_cidr(cidr))
        {
            reply::stock_reply(reply::bad_request, rep);
            return;
        }

        if (op_type == "Add")
        {
            cidr_db_.get()->put(cidr);
            cidr_db_.get()->commit();
        }
        else if (op_type == "Delete")
        {
            cidr_db_.get()->del(cidr);
            cidr_db_.get()->commit();
        }

        std::string present(cidr_db_.get()->has(cidr) ? "true" : "false");

        if (accept_type == mime_types::extension_to_type("json"))
        {
            rep.content.append("{\"cidr\":\"");
            rep.content.append(cidr);
            rep.content.append("\",\"valid\": true,");
            rep.content.append("\"present\":");
            rep.content.append(present);
            rep.content.append("}");
        }
        else if (accept_type == mime_types::extension_to_type("yaml"))
        {
            rep.content.append("---\n");
            rep.content.append("cidr: ");
            rep.content.append(cidr);
            rep.content.append("\n");
            rep.content.append("valid: true");
            rep.content.append("\n");
            rep.content.append("present: ");
            rep.content.append(present);
            rep.content.append("\n");
        }

        rep.content.append("\n");
        rep.headers.resize(3);
        rep.headers[0].name = "X-Operation";
        rep.headers[0].value = op_type;
        rep.headers[1].name = "Content-Length";
        rep.headers[1].value = std::to_string(rep.content.size());
        rep.headers[2].name = "Content-Type";
        rep.headers[2].value = accept_type;
        rep.status = reply::ok;

        return;
    }

    reply::stock_reply(reply::bad_request, rep);
    return;
}

bool request_handler::url_decode(const std::string &in, std::string &out)
{
  out.clear();
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i)
  {
    if (in[i] == '%')
    {
      if (i + 3 <= in.size())
      {
        int value = 0;
        std::istringstream is(in.substr(i + 1, 2));
        if (is >> std::hex >> value)
        {
          out += static_cast<char>(value);
          i += 2;
        }
        else
        {
          return false;
        }
      }
      else
      {
        return false;
      }
    }
    else if (in[i] == '+')
    {
      out += ' ';
    }
    else
    {
      out += in[i];
    }
  }
  return true;
}


void request_handler::query_tokenize(const std::string& in, params_map& out)
{
  bool in_option_name = true;
  std::string option_name;
  std::string option_value;

  for (std::size_t i = 0; i < in.size(); ++i)
  {
    if (in_option_name)
    {
      // parsing the name of an option
      if (in[i] == '=')
      {
        in_option_name = false;
      }
      else if (in[i] == '&')
      {
        out[option_name] = ""; // option without value
        option_name.clear ();
      }
      else
      {
        option_name += in[i];
      }
    }
    else
    {
      // parsing the value of an option
      if (in[i] == '&')
      {
        out[option_name] = option_value; // option with value
        option_name.clear ();
        option_value.clear ();
        in_option_name = true;
      }
      else
      {
        option_value += in[i];
      }
    }
  }

  if (false == option_name.empty())
  {
    out[option_name] = option_value; // last option with or without value
  }
}

/// Register a dynamic resource (a code generated web page)
void request_handler::register_resource(const std::string& resource_name, resource_function&& function)
{
  resource_map_.insert(std::pair<std::string, resource_function>(resource_name, std::move(function)));
}

/// Unregister a dynamic resource
void request_handler::unregister_resource(const std::string& resource_name)
{
  resource_map::iterator resource = resource_map_.find(resource_name);
  if (resource_map_.end() != resource)
  {
    resource_map_.erase(resource);
  }
}

} // namespace server
} // namespace http
