#ifdef RODS_SERVER
#include "handshake_client.h"
#include <string>
#include <tuple>
#include <iostream>

#include "rodsLog.h"

#include "pam_handshake/server.h"

using namespace PamHandshake;

static std::shared_ptr<Server> getInstance(bool verbose)
{
  return Server::getInstance("irods",
                             "/usr/sbin/pam_handshake_auth_check",
                             10,
                             10000,
                             36000,
                             verbose);
}

std::tuple<int, std::string> PamHandshake::open_pam_handshake_session(bool unixSocket,
                                                                      const std::string & addr,
                                                                      long port,
                                                                      bool verbose)
{
  //@todo just return std::string or throw exception
  auto server = getInstance(verbose);
  std::string session = server->createSession();
  return std::make_tuple(200, session);
}

std::tuple<int, std::string, std::string> PamHandshake::pam_handshake_get(bool unixSocket,
                                                                          const std::string & addr,
                                                                          long port,
                                                                          const std::string & session,
                                                                          bool verbose)
{
  //@todo return state or message or throw
  auto server = getInstance(verbose);
  try
  {
    auto s = server->getState(session);
    return std::make_tuple(200, Session::StateToString(s), "");
  }
  catch(const InvalidToken & ex)
  {
    return std::make_tuple(404,
                           Session::StateToString(Session::State::Error),
                           ex.what());
  }
}


std::tuple<int, std::string, std::string> PamHandshake::pam_handshake_put(bool unixSocket,
                                                                          const std::string & addr,
                                                                          long port,
                                                                          const std::string & session,
                                                                          const std::string & input,
                                                                          bool verbose)
{
  //@todo return state or message or throw
  auto server = getInstance(verbose);
  auto p = server->pull(session, input);

  
  //@todo use exception instead of http code
  int http_code = 200;
  if(p.first == Session::State::NotAuthenticated)
  {
    http_code = 401;
  }
  else if(p.first == Session::State::Authenticated)
  {
    http_code = 202;
  }
  else if(p.first == Session::State::Error)
  {
    http_code = 500;
  }
  return std::make_tuple(http_code,
                         Session::StateToString(p.first),
                         p.second);
}

int PamHandshake::pam_handshake_delete(bool unixSocket,
                                       const std::string & addr,
                                       long port,
                                       const std::string & session,
                                       bool verbose)
{
  auto server = getInstance(verbose);
  try
  {
    server->deleteSession(session);
    return 200;
  }
  catch(const InvalidToken & ex)
  {
    return 500;
  }
}

#endif
