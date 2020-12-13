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

request_handler::request_handler(std::shared_ptr<cidr::db> &cidr_db)
  : cidr_db_(cidr_db)
  { }

void request_handler::handle_request(const request &req, reply &rep)
{
  // decode URI to path
  std::string request_path;
  if (!url_decode(req.uri, request_path))
  {
    reply::stock_reply(reply::bad_request, rep);
    return;
  }

  // the only URI path supported is: /
  if (request_path != "/")
  {
    reply::stock_reply(reply::not_found, rep);
    return;
  }

  std::string accept_type(mime_types::extension_to_type("json"));

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

  if (req.method == "GET")
  {
    rep.status = reply::ok;
    rep.content.append("{\"status\":\"OK\"}\n");
    rep.headers.resize(2);
    rep.headers[0].name = "Content-Length";
    rep.headers[0].value = std::to_string(rep.content.size());
    rep.headers[1].name = "Content-Type";
    rep.headers[1].value = mime_types::extension_to_type("json");
    return;
  }

  if (req.method == "POST")
  {
    // Decode and tokenize the content part of the POST request
    std::string content;
    if (!url_decode(req.content, content))
    {
        reply::stock_reply(reply::bad_request, rep);
        return;
    }

    std::vector<std::string> lines;
    ba::split(lines, content, b::is_any_of("\r\n"));

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

        rep.content.append("]\n");
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

        rep.content.append("\n");
    }

    rep.headers.resize(2);
    rep.headers[0].name = "Content-Length";
    rep.headers[0].value = std::to_string(rep.content.size());
    rep.headers[1].name = "Content-Type";
    rep.headers[1].value = accept_type;
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
  bool        in_option_name = true;
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
