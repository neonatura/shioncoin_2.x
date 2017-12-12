
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "config.h"

#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/signals2.hpp>

#include "shcoind.h"
#include "main.h"
#include "wallet.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "rpccert_proto.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "mnemonic.h"
#include "rpcnet.h"

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;
using namespace boost::assign;

#include "SSLIOStreamDevice.h"

static boost::asio::io_service rpc_service;
boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(rpc_service));
boost::asio::ssl::context context(rpc_service, boost::asio::ssl::context::sslv23);

extern json_spirit::Value rpc_execute(CIface *iface, const std::string &strMethod, json_spirit::Array &params);


vector<AcceptedConnection *>vRPCConn;

class JSONRequest
{
public:
    Value id;
    string strMethod;
    Array params;
    CIface *iface;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

// Forward declaration for RPC_Listen
template <typename Protocol, typename SocketAcceptorService>
static void RPC_AcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context& context, bool fUseSSL, AcceptedConnection* conn, const boost::system::error_code& error);

// Forward declaration for RPC_AcceptHandler
template <typename Protocol, typename SocketAcceptorService>
static void RPC_Listen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context& context, const bool fUseSSL);



void RPC_CloseConnection(AcceptedConnection *conn)
{
  int idx;

  for (idx = 0; idx < vRPCConn.size(); idx++) {
    if (vRPCConn[idx] == conn)
      break;
  }
  if (idx == vRPCConn.size())
    return;

  vRPCConn.erase(vRPCConn.begin() + idx);
  conn->close();
  delete conn;
}

static int RPC_ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return 500;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

static int RPC_ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    loop
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

static int RPC_ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nProto = 0;
    int nStatus = RPC_ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = RPC_ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return 500;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

static string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want posix (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
  if (nStatus == 401)
    return strprintf("HTTP/1.0 401 Authorization Required\r\n"
        "Date: %s\r\n"
        "Server: shcoind-json-rpc/%s\r\n"
        "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 296\r\n"
        "\r\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
        "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
        "<HTML>\r\n"
        "<HEAD>\r\n"
        "<TITLE>Error</TITLE>\r\n"
        "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
        "</HEAD>\r\n"
        "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
        "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
  const char *cStatus;
  if (nStatus == 200) cStatus = "OK";
  else if (nStatus == 400) cStatus = "Bad Request";
  else if (nStatus == 403) cStatus = "Forbidden";
  else if (nStatus == 404) cStatus = "Not Found";
  else if (nStatus == 500) cStatus = "Internal Server Error";
  else cStatus = "";
  return strprintf(
      "HTTP/1.1 %d %s\r\n"
      "Date: %s\r\n"
      "Connection: %s\r\n"
      "Content-Length: %d\r\n"
      "Content-Type: application/json\r\n"
      "Server: shcoind-json-rpc/%s\r\n"
      "\r\n"
      "%s",
      nStatus,
      cStatus,
      rfc1123Time().c_str(),
      keepalive ? "keep-alive" : "close",
      strMsg.size(),
      FormatFullVersion().c_str(),
      strMsg.c_str());
}

static bool RPC_HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    string strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    return strUserPass == strRPCUserColonPass;
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
  Object reply = JSONRPCReplyObj(result, error, id);
  return write_string(Value(reply), false) + "\n";
}

static void RPC_ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = 500;
    int code = find_value(objError, "code").get_int();
    if (code == -32600) nStatus = 400;
    else if (code == -32601) nStatus = 404;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

extern Object JSONRPCError(int code, const string& message);

static Object RPC_JSONRPCExecOne(const Value& req)
{
  Object rpc_result;

  JSONRequest jreq;
  try {
    jreq.parse(req);

    Value result = rpc_execute(jreq.iface, jreq.strMethod, jreq.params);
    rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
  }
  catch (Object& objError)
  {
    rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
  }
  catch (std::exception& e)
  {
    rpc_result = JSONRPCReplyObj(Value::null,
        JSONRPCError(-32700, e.what()), jreq.id);
  }

  return rpc_result;
}

static string RPC_JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(RPC_JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

void RPC_ProcessConnection(AcceptedConnection *conn)
{
  bool fRun = true;

  map<string, string> mapHeaders;
  string strRequest;

  RPC_ReadHTTP(conn->stream(), mapHeaders, strRequest);

  // Check authorization
  if (mapHeaders.count("authorization") == 0)
  {
    conn->stream() << HTTPReply(401, "", false) << std::flush;
    RPC_CloseConnection(conn);
    return;
  }
  if (!RPC_HTTPAuthorized(mapHeaders))
  {
    //Debug("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string().c_str());
    conn->stream() << HTTPReply(401, "", false) << std::flush;
    RPC_CloseConnection(conn);
    return;
  }
  if (mapHeaders["connection"] == "close")
    fRun = false;

  JSONRequest jreq;
  try
  {
    // Parse request
    Value valRequest;
    if (!read_string(strRequest, valRequest))
      throw JSONRPCError(-32700, "Parse error");

    string strReply;

    // singleton request
    if (valRequest.type() == obj_type) {
      jreq.parse(valRequest);

      Value result = rpc_execute(jreq.iface, jreq.strMethod, jreq.params);

      // Send reply
      strReply = JSONRPCReply(result, Value::null, jreq.id);

      // array of requests
    } else if (valRequest.type() == array_type)
      strReply = RPC_JSONRPCExecBatch(valRequest.get_array());
    else
      throw JSONRPCError(-32700, "Top-level object parse error");

    conn->stream() << HTTPReply(200, strReply, fRun) << std::flush;
  }
  catch (Object& objError)
  {
    RPC_ErrorReply(conn->stream(), objError, jreq.id);
    RPC_CloseConnection(conn);
    return;
  }
  catch (std::exception& e)
  {
    RPC_ErrorReply(conn->stream(), JSONRPCError(-32700, e.what()), jreq.id);
    RPC_CloseConnection(conn);
    return;
  }

  if (!fRun) {
    RPC_CloseConnection(conn);
  }
}

static bool RPC_ClientAllowed(const boost::asio::ip::address& address)
{
  // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
  if (address.is_v6()
      && (address.to_v6().is_v4_compatible()
        || address.to_v6().is_v4_mapped()))
    return RPC_ClientAllowed(address.to_v6().to_v4());

  if (address == boost::asio::ip::address_v4::loopback()
      || address == boost::asio::ip::address_v6::loopback()
      || (address.is_v4()
        // Chech whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
        && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
    return true;

  const string strAddress = address.to_string();
  const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
  BOOST_FOREACH(string strAllow, vAllow)
    if (WildcardMatch(strAddress, strAllow))
      return true;
  return false;
}

void RPC_AddConnection(AcceptedConnection *conn)
{
  vRPCConn.push_back(conn);
}

template <typename Protocol, typename SocketAcceptorService>
static void RPC_AcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             boost::asio::ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& err)
{

  // Immediately start accepting new connections, except when we're canceled or our socket is closed.
  if (err != boost::asio::error::operation_aborted
      && acceptor->is_open())
    RPC_Listen(acceptor, context, fUseSSL);

  if (err)
  {
fprintf(stderr, "DEBUG: RPC_AcceptHandler: error '%s'\n", err.message().c_str());
    delete conn;
    return;
  }

  AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn);

  if (!tcp_conn) {
fprintf(stderr, "DEBUG: RPC_AcceptHandler: !tcp_conn\n");
    delete conn;
    return;
  }

  // Restrict callers by IP.  It is important to
  // do this before starting client thread, to filter out
  // certain DoS and misbehaving clients.
  if (!RPC_ClientAllowed(tcp_conn->peer.address()))
  {
    // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
    if (!fUseSSL)
      conn->stream() << HTTPReply(403, "", false) << std::flush;
fprintf(stderr, "DEBUG: RPC_AcceptHandler: !RPC_CLientAllowed\n"); 
    delete conn;
    return;
  }

  RPC_AddConnection(conn);

}

template <typename Protocol, typename SocketAcceptorService>
static void RPC_Listen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context& context, const bool fUseSSL)
{
  // Accept connection
  AcceptedConnectionImpl<Protocol>* conn = new AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);

  acceptor->async_accept(
      conn->sslStream.lowest_layer(),
      conn->peer,
      boost::bind(&RPC_AcceptHandler<Protocol, SocketAcceptorService>,
        acceptor,
        boost::ref(context),
        fUseSSL,
        conn,
        boost::asio::placeholders::error));
}

void RPC_Init(void)
{

  //strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
  if (mapArgs["-rpcpassword"] == "")
  {
    return;
  }

  const bool fUseSSL = GetBoolArg("-rpcssl");


  if (fUseSSL)
  {
    context.set_options(boost::asio::ssl::context::no_sslv2);

    filesystem::path pathCertFile(GetArg("-rpcsslcertificatechainfile", "server.cert"));
    if (!pathCertFile.is_complete()) pathCertFile = filesystem::path(GetDataDir()) / pathCertFile;
    if (filesystem::exists(pathCertFile)) context.use_certificate_chain_file(pathCertFile.string());
    else fprintf(stderr, "ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());

    filesystem::path pathPKFile(GetArg("-rpcsslprivatekeyfile", "server.pem"));
    if (!pathPKFile.is_complete()) pathPKFile = filesystem::path(GetDataDir()) / pathPKFile;
    if (filesystem::exists(pathPKFile)) context.use_private_key_file(pathPKFile.string(), boost::asio::ssl::context::pem);
    else fprintf(stderr, "ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());

    string strCiphers = GetArg("-rpcsslciphers", "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
    SSL_CTX_set_cipher_list(context.impl(), strCiphers.c_str());
  }

  // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
  const bool loopback = !mapArgs.count("-rpcallowip");
  boost::asio::ip::address bindAddress = loopback ? boost::asio::ip::address_v6::loopback() : boost::asio::ip::address_v6::any();
  ip::tcp::endpoint endpoint(bindAddress, opt_num(OPT_RPC_PORT));
  boost::system::error_code v6_only_error;

  boost::signals2::signal<void ()> StopRequests;

  bool fListening = false;
  std::string strerr;
  try
  {
    acceptor->open(endpoint.protocol());
    acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

    // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
    acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

    acceptor->bind(endpoint);
    acceptor->listen(socket_base::max_connections);

    RPC_Listen(acceptor, context, fUseSSL);
    // Cancel outstanding listen-requests for this acceptor when shutting down
    StopRequests.connect(signals2::slot<void ()>(
          static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
        .track(acceptor));

    fListening = true;
  }
  catch(boost::system::system_error &e)
  {
    //Debug("An error occurred while setting up the RPC port %d for listening on IPv6, falling back to IPv4: %s", (int)endpoint.port(), e.what());
  }

  try {
    // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
    if (!fListening || loopback || v6_only_error)
    {
      bindAddress = loopback ? boost::asio::ip::address_v4::loopback() : boost::asio::ip::address_v4::any();
      endpoint.address(bindAddress);

      acceptor.reset(new ip::tcp::acceptor(rpc_service));
      acceptor->open(endpoint.protocol());
      acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
      acceptor->bind(endpoint);
      acceptor->listen(socket_base::max_connections);

      RPC_Listen(acceptor, context, fUseSSL);
      // Cancel outstanding listen-requests for this acceptor when shutting down
      StopRequests.connect(signals2::slot<void ()>(
            static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
          .track(acceptor));

      fListening = true;
    }
  }
  catch(boost::system::system_error &e)
  {
    //Debug("An error occurred while setting up the RPC port %d for listening on IPv4: %s", (int)endpoint.port(), e.what());
  }

}

#ifdef __cplusplus
extern "C" {
#endif
void RPC_CycleConnections(void)
{
  vector<AcceptedConnection *>vCopy;

  rpc_service.poll_one();

  BOOST_FOREACH(AcceptedConnection *conn, vRPCConn) {
    vCopy.push_back(conn);
  }
  BOOST_FOREACH(AcceptedConnection *conn, vCopy) {
    RPC_ProcessConnection(conn);
  }

}
#ifdef __cplusplus
}
#endif



