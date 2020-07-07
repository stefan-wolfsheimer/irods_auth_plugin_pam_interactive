#pragma once
#include <json.hpp>
#include <iostream>
#include <stdexcept>
#include "irods_kvp_string_parser.hpp"
#define PAMLOG_DEBUG 2
#define PAMLOG_INFO 1

#define PAM_CLIENT_LOG(LEVEL, X)                                      \
  {                                                                   \
    if(VERBOSE_LEVEL >= LEVEL)                                        \
    {                                                                 \
      std::cout << "PAM: " << __FILE__ << ":" << __LINE__ << " ";     \
      std::cout << X;                                                 \
      std::cout << std::endl;                                         \
    }                                                                 \
  }

namespace PamHandshake
{
  class MessageError : public std::runtime_error
  {
  public:
    inline MessageError(const std::string & msg) : std::runtime_error(msg) {}
  };

  class ParseError : public MessageError
  {
  public:
    inline ParseError(const std::string & msg)
      : MessageError(std::string("failed to parse message: ") + msg) {}
  };

  class HttpError : public MessageError
  {
  public:
    inline HttpError(const std::string & code = "")
      : MessageError(code.empty() ? std::string("No code") : (std::string("HTTP code: ") + code)) {}
  };

  class StateError : public MessageError
  {
  public:
    inline StateError(const std::string & state = "")
      : MessageError(state.empty() ? std::string("No state") : (std::string("invalid state: ") + state)) {}
  };

  class InvalidKeyError : public MessageError
  {
  public:
    inline InvalidKeyError(const std::string & key = "")
      : MessageError(std::string("invalid key:") + key) {}
  };

  class Message
  {
  public:
    // message types:
    // case 1: [^{].*
    //    display message (update configuration file if state is Waiting or WaitingPw)
    //    <str> is tranlated to
    //    {"echo": <str>,
    //     "ask": "always",
    //     "update": <str>}
    // case 2: {"echo": "display message",
    //          "patch": {"key": {...}, "key": {}},
    //          "ask": "always",
    //          "update": "key",
    //          "valid_until": "yyyy-mm-dd"}
    //
    // echo: echo message (if in echo mode)
    // save: patch list of cookies on client side
    // if state is "Waiting" or "WaitingPw":
    //    ask: "never" / "always" / "when invalid"
    //    update: "key" 
    //        if cookie if user has answered update cookie with that key
    //    valid_until: "date-time"
    //        if cookie if user has answered update cookie expiration

    enum class State
    {
      Running,
      Ready,
      Waiting,
      WaitingPw,
      Answer,
      Next,
      Error,
      Timeout,
      Authenticated,
      NotAuthenticated
    };
    enum class AnswerMode
    {
      Always,
      Never,
      WhenInvalid
    };

    Message(const std::string & msg);

    inline State getState() const
    {
      return state;
    }

    inline const std::string & getMessage() const
    {
      return message;
    }

    inline const std::string & getUpdateKey() const
    {
      return update_key;
    }

    inline bool hasEcho() const
    {
      return has_echo;
    }

    inline AnswerMode getAnswerMode() const
    {
      return answer_mode;
    }

    inline const nlohmann::json & getCookies() const
    {
      return cookies;
    }

  private:
    void parseJson();
    irods::kvp_map_t kvp;
    State state;
    std::string message;
    std::string update_key;
    AnswerMode answer_mode;
    bool has_echo;
    nlohmann::json cookies;
  };
  
  std::string get_conversation_file();
  /**
   * Update cookies in json configuration
   *
   * update / add /delete:
   * cookies = {key1: {value: <value>, valid_until: <datetime>},
                key2: {value: <value>},
                key3: null}
   */
  void update_cookies(nlohmann::json & j,
                      const nlohmann::json & cookies);
  std::string pam_input(const std::string & message, nlohmann::json & j, bool do_echo=true);
  std::string pam_input_password(const std::string & message, nlohmann::json & j, bool do_echo=true);


  // save conversation to file / output stream
  void save_conversation(const nlohmann::json & json_conversation,
                         int VERBOSE_LEVEL);
  void save_conversation(std::ostream & ost,
                         const nlohmann::json & json_conversation);

  // load conversation from file / input stream
  nlohmann::json load_conversation(int VERBOSE_LEVEL);
  nlohmann::json load_conversation(std::istream & ist);

}
