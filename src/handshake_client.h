#pragma once
#include <string>

#ifdef RODS_SERVER
#include <tuple>
#endif

namespace PamHandshake
{
#ifdef RODS_SERVER  
  std::tuple<int, std::string> open_pam_handshake_session(bool unixSocket,
                                                          const std::string & addr,
                                                          long port,
                                                          bool verbose);
  std::tuple<int, std::string, std::string> pam_handshake_get(bool unixSocket,
                                                              const std::string & addr,
                                                              long port,
                                                              const std::string & session,
                                                              bool verbose);
  std::tuple<int, std::string, std::string> pam_handshake_put(bool unixSocket,
                                                              const std::string & addr,
                                                              long port,
                                                              const std::string & session,
                                                              const std::string & input,
                                                              bool verbose);
  int pam_handshake_delete(bool unixSocket,
                           const std::string & addr,
                           long port,
                           const std::string & session,
                           bool verbose);


#endif
}
