#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <json.hpp>
#include <termios.h>
#include "pam_interactive_config.h"
#include "getRodsEnv.h"
#include "authenticate.h"
#include "obf.h"
#include "rodsErrorTable.h"

//@todo make configurable and share between client and server
#define OBF_KEY "1234567890"

/////////////////////////////////////////////////////////////
//
// Conversation
//
/////////////////////////////////////////////////////////////
PamHandshake::Conversation::Conversation()
  : is_dirty(false), j("{}"_json)
{
}

PamHandshake::Conversation::Conversation(const nlohmann::json & rhs)
  : is_dirty(false), j(rhs)
{
}

PamHandshake::Conversation::Conversation(nlohmann::json && rhs)
  : is_dirty(false), j(std::move(rhs))
{
}

void PamHandshake::Conversation::load(int VERBOSE_LEVEL)
{
  std::string file_name(getConversationFile());
  PAM_CLIENT_LOG(PAMLOG_INFO, "LOAD  conversation: " << file_name);
  std::ifstream file(file_name.c_str());
  if (file.is_open())
  {
    load(file);
    file.close();
  }
}

void PamHandshake::Conversation::load(std::istream & ist)
{
  ist >> j;
}

void PamHandshake::Conversation::reset()
{
  j = "{}"_json;
}

void PamHandshake::Conversation::save(int VERBOSE_LEVEL, bool force)
{
  if(is_dirty || force)
  {
    std::string file_name(getConversationFile());
    PAM_CLIENT_LOG(PAMLOG_INFO, "SAVE conversation: " << file_name);
    std::ofstream file(file_name.c_str());
    if (file.is_open())
    {
      file << j;
      file.close();
    }
    else
    {
      throw std::runtime_error((std::string("cannot write to  file ") + file_name).c_str());
    }
  }
  is_dirty = false;
}

std::string PamHandshake::Conversation::dump() const
{
  std::stringstream ss;
  ss << j;
  return ss.str();
}

std::tuple<bool, std::string> PamHandshake::Conversation::getValue(const std::string & key) const
{
  //@todo decode value
  if(j.contains(key))
  {
    if(j[key].is_string())
    {
      return std::make_tuple(true, j[key].get<std::string>());
    }
    else if(j[key].is_object())
    {
      if(j[key].contains("value"))
      {
        return std::make_tuple(true, j[key]["value"].get<std::string>());
      }
    }
  }
  return std::make_tuple(false, "");
}

std::tuple<bool, std::string> PamHandshake::Conversation::getValidUntil(const std::string & key) const
{
  if(j.contains(key))
  {
    if(j[key].is_string())
    {
      return std::make_tuple(true, j[key].get<std::string>());
    }
    else if(j[key].is_object())
    {
      if(j[key].contains("valid_until"))
      {
        return std::make_tuple(true, j[key]["valid_until"].get<std::string>());
      }
    }
  }
  return std::make_tuple(false, "");
}

void PamHandshake::Conversation::setValue(const std::string & key,
                                          const std::string & value,
                                          const std::string & valid_until)
{
  if(valid_until.empty())
  {
    j[key] = nlohmann::json::object({
        {"value", value},
        {"scrambled", false}});
  }
  else
  {
    j[key] = nlohmann::json::object({
        {"value", value},
        {"scrambled", false},
        {"valid_until", valid_until}});
  }
}


bool PamHandshake::Conversation::isDirty() const
{
  return is_dirty;
}

std::string PamHandshake::Conversation::getConversationFile() const
{
  char *envVar = getRodsEnvAuthFileName();
  if(envVar && *envVar != '\0')
  {
    return std::string(envVar);
  }
  else
  {
    return std::string(getenv( "HOME" )) + "/.irods/.irodsA.json";
  }
}

/////////////////////////////////////////////////////////////
//
// Message
//
/////////////////////////////////////////////////////////////
inline static PamHandshake::Message::State parseState(const std::string & s)
{
  using State = PamHandshake::Message::State;
  if(s == "RUNNING")
  {
    return State::Running;
  }
  else if(s == "READY")
  {
    return State::Ready;
  }
  else if(s == "RUNNING")
  {
    return State::Running;
  }
  else if(s == "WAITING")
  {
    return State::Waiting;
  }
  else if(s == "WAITING_PW")
  {
    return State::WaitingPw;
  }
  else if(s == "ANSWER")
  {
    return State::Answer;
  }
  else if(s == "NEXT")
  {
    return State::Next;
  }
  else if(s == "ERROR")
  {
    return State::Error;
  }
  else if(s == "TIMEOUT")
  {
    return State::Timeout;
  }
  else if(s == "STATE_AUTHENTICATED")
  {
    return State::Authenticated;
  }
  else if(s == "NOT_AUTHENTICATED")
  {
    return State::NotAuthenticated;
  }
  else
  {
    throw PamHandshake::StateError(s);
  }
}

PamHandshake::Message::Message(const std::string & msg)
{
  irods::error ret = irods::parse_escaped_kvp_string(msg, kvp);
  if(!ret.ok())
  {
    throw ParseError(msg);
  }
  auto itr = kvp.find("CODE");
  if(itr == kvp.end())
  {
    throw HttpError();
  }
  if(itr->second != "200" && itr->second != "401" && itr->second != "202")
  {
    throw HttpError(itr->second);
  }
  itr = kvp.find("STATE");
  if(itr == kvp.end())
  {
    throw StateError();
  }
  state = ::parseState(itr->second);
  itr = kvp.find("MESSAGE");
  answer_mode = ResponseMode::User;
  if(itr != kvp.end())
  {
    message = itr->second;
  }
  if(message.empty())
  {
    key = "null"_json;
  }
  else if(message[0] != '{')
  {
    key = message;
  }
  else
  {
    parseJson();
  }
}

bool PamHandshake::Message::needUpdateInput(const nlohmann::json & j,
                                            const std::string & k,
                                            const std::string & a) const
{
  if(valid_until.is_null())
  {
    if(j.contains(k) &&
       j[k].is_object() &&
       j[k].contains("value") &&
       j[k]["value"].get<std::string>() == a)
    {
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    if(j.contains(k) &&
       j[k].is_object() &&
       j[k].contains("value") &&
       j[k]["value"].get<std::string>() == a &&
       j[k].contains("valid_until") &&
       j[k]["valid_until"].get<std::string>() == valid_until.get<std::string>())
    {
      return false;
    }
    else
    {
      return true;
    }
  }
}

std::string PamHandshake::Message::input(Conversation & c,
                                         bool do_echo,
                                         std::istream & ist,
                                         std::ostream & ost) const
{
  std::string ret;
  bool is_dirty;
  std::tie(is_dirty, ret) = input(c.j, do_echo, ist, ost);
  c.is_dirty |= is_dirty;
  return ret;
}
std::string PamHandshake::Message::input_password(Conversation & c,
                                                  bool do_echo,
                                                  std::istream & ist,
                                                  std::ostream & ost) const
{
  std::string ret;
  bool is_dirty;
  std::tie(is_dirty, ret) = input_password(c.j, do_echo, ist, ost);
  c.is_dirty |= is_dirty;
  return ret;
}

std::tuple<bool, std::string> PamHandshake::Message::input(nlohmann::json & j,
                                                           bool do_echo,
                                                           std::istream & ist,
                                                           std::ostream & ost) const
{
  std::string answer;
  auto default_answer = std::make_pair<bool, std::string>(false, "");
  if(key.is_string())
  {
    default_answer = extractDefaultValue(key.get<std::string>(), j);
  }
  if(answer_mode == ResponseMode::Entry)
  {
    // never ask user for input
    // get answer from json or return empty
    if(default_answer.first)
    {
      return std::make_tuple(false, default_answer.second);
    }
    else
    {
      return std::make_tuple(false, answer);
    }
  }
  else
  {
    if(!default_answer.first || do_echo)
    {
      ost << message;
      if(default_answer.first)
      {
        ost << "[" << default_answer.second << "]";
      }
      std::getline(ist, answer);
    }
    if(default_answer.first && answer.empty())
    {
      answer = default_answer.second;
    }
    if(key.is_string())
    {
      std::string k(key.get<std::string>());
      if(needUpdateInput(j, k, answer))
      {
        if(valid_until.is_null())
        {
          j[k] = {{"value", answer},
                  {"scrambled", false}};
        }
        else
        {
          j[k] = {{"value", answer},
                  {"scrambled", false},
                  {"valid_until", valid_until.get<std::string>()}};
        }
        return std::make_tuple(true, answer);
      }
    }
    return std::make_tuple(false, answer);
  }
}

std::tuple<bool, std::string> PamHandshake::Message::input_password(nlohmann::json & j,
                                                                    bool do_echo,
                                                                    std::istream & ist,
                                                                    std::ostream & ost) const
{
  std::string answer;
  auto default_answer = std::make_pair<bool, std::string>(false, "");
  if(key.is_string())
  {
    default_answer = extractDefaultValue(key.get<std::string>(), j);
  }
  if(answer_mode == ResponseMode::Entry)
  {
    // never ask user for input
    // get answer from json or return empty string
    if(default_answer.first)
    {
      return std::make_tuple(false, default_answer.second);
    }
    else
    {
      return std::make_tuple(false, answer);
    }
  }
  else
  {
    if(!default_answer.first || do_echo)
    {
      // either answer not been defined or do_echo is true
      ost << message;
      if(default_answer.first)
      {
        ost << "[****]";
      }
#ifdef WIN32
      HANDLE hStdin = GetStdHandle( STD_INPUT_HANDLE );
      DWORD mode;
      GetConsoleMode( hStdin, &mode );
      DWORD lastMode = mode;
      mode &= ~ENABLE_ECHO_INPUT;
      BOOL error = !SetConsoleMode( hStdin, mode );
      int errsv = -1;
#else
      struct termios tty;
      tcgetattr( STDIN_FILENO, &tty );
      tcflag_t oldflag = tty.c_lflag;
      tty.c_lflag &= ~ECHO;
      int error = tcsetattr( STDIN_FILENO, TCSANOW, &tty );
      int errsv = errno;
      if(error)
      {
        printf( "WARNING: Error %d disabling echo mode. Password will be displayed in plaintext.", errsv );
      }
#endif
      std::getline(ist, answer);
#ifdef WIN32
      if (!SetConsoleMode(hStdin, lastMode))
      {
        printf( "Error reinstating echo mode." );
      }
#else
      tty.c_lflag = oldflag;
      if ( tcsetattr( STDIN_FILENO, TCSANOW, &tty ) )
      {
        printf( "Error reinstating echo mode." );
      }
#endif
      ost << std::endl << std::flush;
    }
    if(default_answer.first && answer.empty())
    {
      answer = default_answer.second;
    }
    if(answer.size() > MAX_PASSWORD_LEN)
    {
      answer.erase(MAX_PASSWORD_LEN);
    }
    if(key.is_string())
    {
      char * pw = new char[answer.size() + 10];
      obfEncodeByKey(answer.c_str(),
                     OBF_KEY,
                     pw);
      std::string k(key.get<std::string>());
      std::string enc_answer(pw);
      delete [] pw;
      if(needUpdateInput(j, k, enc_answer))
      {
        if(valid_until.is_null())
        {
          j[k] = {{"value", enc_answer},
                  {"scrambled", true}};
          return std::make_tuple(true, answer);
        }
        else
        {
          j[k] = {{"value", enc_answer},
                  {"scrambled", true},
                  {"valid_until", valid_until.get<std::string>()}};
          return std::make_tuple(true, answer);
        }
      }
    }
    return std::make_tuple(false, answer);
  }
}

bool PamHandshake::Message::applyPatch(Conversation & c) const
{
  bool ret = applyPatch(c.j);
  c.is_dirty |= ret;
  return ret;
}

bool PamHandshake::Message::applyPatch(nlohmann::json & j) const
{
  if(patch.is_null())
  {
    return false;
  }
  else if(patch.is_object())
  {
    bool ret = false;
    for(auto item : patch.items())
    {
      if(item.value().is_null())
      {
        if(j.find(item.key()) != j.end())
        {
          j.erase(item.key());
          ret = true;
        }
      }
      else
      {
        j.merge_patch(nlohmann::json{{item.key(), item.value()}});
        ret = true;
      }
    }
    return ret;
  }
  else
  {
    throw InvalidKeyError(std::string("expected object:") + patch.dump());
  }
}


void PamHandshake::Message::parseJson()
{
  auto obj = nlohmann::json::parse(message);
  message = "";
  answer_mode = ResponseMode::User;
  for(auto item : obj.items() )
  {
    const std::string & k(item.key());
    if(k == "echo")
    {
      message = item.value().get<std::string>();
    }
    else if(k == "patch")
    {
      patch = item.value();
    }
    else if(k == "ask")
    {
      std::string ask(item.value().get<std::string>());
      if(ask == "user")
      {
        answer_mode = ResponseMode::User;
      }
      else if(ask == "entry")
      {
        answer_mode = ResponseMode::Entry;
      }
      else
      {
        throw InvalidKeyError(ask);
      }
    }
    else if(k == "key")
    {
      key = item.value();
    }
    else if(k == "valid_until")
    {
      valid_until = item.value();
    }
    else
    {
      throw InvalidKeyError(item.key());
    }
  }
}

std::pair<bool, std::string> PamHandshake::Message::extractDefaultValue(const std::string & key,
                                                                        const nlohmann::json & j) const
{
  if(j.contains(key))
  {
    if(j[key].is_string())
    {
      return std::make_pair(true, j[key].get<std::string>());
    }
    else if(j[key].is_object() &&
            j[key].contains("value") &&
            j[key]["value"].is_string())
    {
      if(j[key].contains("scrambled") &&
         j[key]["scrambled"].get<bool>())
      {
        //@todo length check!
        std::string answer(j[key]["value"].get<std::string>());
        if(answer.size() > MAX_PASSWORD_LEN + 9)
        {
          throw std::runtime_error("password too long");
        }
        char * pw = new char[answer.size() + 1];
        obfDecodeByKey(answer.c_str(),
                       OBF_KEY,
                       pw);
        std::string ret(pw);
        delete [] pw;
        return std::make_pair(true, ret);
      }
      else
      {
        return std::make_pair(true, j[key]["value"].get<std::string>());
      }
    }
    return std::make_pair(false, std::string(""));
  }
  else
  {
    return std::make_pair(false, std::string(""));
  }
}
