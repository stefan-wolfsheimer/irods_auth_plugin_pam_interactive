#pragma once
#include <json.hpp>
#include <iostream>
#include <stdexcept>
#include "irods_kvp_string_parser.hpp"
#define PAMLOG_DEBUG 2
#define PAMLOG_INFO 1
#define PAMLOG_ERROR 0

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

  class Conversation
  {
  public:
    Conversation();
    Conversation(const nlohmann::json & rhs);
    Conversation(nlohmann::json && rhs);
    void load(int verbose_level);
    void load(std::istream & ist);
    void reset();
    void save(int VERBOSE_LEVEL, bool force=false);
    std::string dump() const;
    std::tuple<bool, std::string> getValue(const std::string & key) const;
    std::tuple<bool, std::string> getValidUntil(const std::string & key) const;
    void setValue(const std::string & key,
                  const std::string & value,
                  const std::string & valid_until="");
    bool isDirty() const;
    std::string getConversationFile() const;

  private:
    friend class Message;
    bool is_dirty;
    nlohmann::json j;
  };

  class Message
  {
  public:
    // message types:
    // --------------
    // case 1: {"echo": "msg",
    //          "ask": "user"}
    // ask user for input and send answer back to server
    // don't save user's answer locally
    //
    // case 1b: {"echo": "msg",
    //           "ask": "user",
    //           "patch": {"key1": {"value": "v1", "valid_until": "2020-12-31"},
    //                     "key2": {"value": "v2"}}
    // same as case 1 and additional saves entries key1 and key2 on client side
    //
    // case 2:
    // {"echo": "msg",
    //  "ask": "user",
    //  "key":  "key1"}
    // ask user for input and send answer back to server
    // save user's answer locally under key1.
    // use value of key1 as default answer.
    //
    // a string that does not represent a json object is translated to
    //    {"echo": <str>,
    //     "ask": "user",
    //     "key":  <str>}
    //
    // case 3: {"echo": "display message",
    //          "ask": "user",
    //          "key": "key",
    //          "valid_until": "yyyy-mm-dd"}
    // ask user and save data locally under "key" with expiration date
    //
    // case 4: {"ask": "entry",
    //          "key": "key"}
    // retrieve entry without user interaction

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
    enum class ResponseMode
    {
      User, Entry
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

    inline const nlohmann::json & getKey() const
    {
      return key;
    }

    inline const nlohmann::json & getValidUntil() const
    {
      return valid_until;
    }

    inline ResponseMode getResponseMode() const
    {
      return answer_mode;
    }

    inline const nlohmann::json & getPatch() const
    {
      return patch;
    }

    /**
     * Update cookies in json configuration
     *
     * update / add /delete:
     * cookies = {key1: {value: <value>, valid_until: <datetime>},
                  key2: {value: <value>},
                  key3: null}
    */
    bool applyPatch(nlohmann::json & j) const;
    bool applyPatch(Conversation & c) const;

    /**
     * Read input from user.
     */
    std::tuple<bool, std::string> input(nlohmann::json & j,
                                        bool do_echo=true,
                                        std::istream & ist=std::cin,
                                        std::ostream & ost=std::cout) const;
    std::string input(Conversation & c,
                      bool do_echo=true,
                      std::istream & ist=std::cin,
                      std::ostream & ost=std::cout) const;
    std::tuple<bool, std::string> input_password(nlohmann::json & j,
                                                 bool do_echo=true,
                                                 std::istream & ist=std::cin,
                                                 std::ostream & ost=std::cout) const;
    std::string input_password(Conversation & c,
                               bool do_echo=true,
                               std::istream & ist=std::cin,
                               std::ostream & ost=std::cout) const;

  private:
    void parseJson();
    std::pair<bool, std::string> extractDefaultValue(const std::string & key,
                                                     const nlohmann::json & j) const;
    bool needUpdateInput(const nlohmann::json & j,
                         const std::string & k,
                         const std::string & a) const;
    irods::kvp_map_t kvp;
    State state;
    std::string message;
    nlohmann::json key;
    nlohmann::json valid_until;
    ResponseMode answer_mode;
    nlohmann::json patch;
  };
}
