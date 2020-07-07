#include <string>
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
  if(itr != kvp.end())
  {
    message = itr->second;
  }
  if(message.empty() || message[0] != '{')
  {
    // simple case: message is a simple string
    has_echo = true;
    update_key = message;
    answer_mode = AnswerMode::Always;
  }
  else
  {
    parseJson();
  }
}

void PamHandshake::Message::parseJson()
{
  auto obj = nlohmann::json::parse(message);
  message = "";
  answer_mode = AnswerMode::Always;
  for(auto item : obj.items() )
  {
    const std::string & key(item.key());
    if(key == "echo")
    {
      message = item.value().get<std::string>();
      has_echo = true;
    }
    else if(key == "patch")
    {
      cookies = item.value();
    }
    else if(key == "ask")
    {
      std::string ask(item.value().get<std::string>());
      if(ask == "always")
      {
        answer_mode = AnswerMode::Always;
      }
      else if(ask == "never")
      {
        answer_mode = AnswerMode::Never;
      }
      else if(ask == "when invalid")
      {
        answer_mode = AnswerMode::WhenInvalid;
      }
      else
      {
        throw InvalidKeyError(ask);
      }
    }
    else if(key == "update")
    {
      update_key = item.value().get<std::string>();
    }
    else if(key == "valid_until")
    {
      //@todo
    }
    else
    {
      throw InvalidKeyError(item.key());
    }
  }
}

static std::string extract_default_value(const std::string & message,
                                         nlohmann::json & j)
{
  if(j.contains(message))
  {
    if(j[message].is_string())
    {
      return j[message].get<std::string>();
    }
    else if(j[message].is_object() &&
            j[message].contains("answer") &&
            j[message]["answer"].is_string())
    {
      if(j[message].contains("scrambled") &&
         j[message]["scrambled"].get<bool>())
      {
        //@todo length check!
        std::string answer(j[message]["answer"].get<std::string>());
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
        return ret;
      }
      else
      {
        return j[message]["answer"].get<std::string>();
      }
    }
  }
  return std::string("");
}

void PamHandshake::update_cookies(nlohmann::json & j,
                                  const nlohmann::json & cookies)
{
  if(cookies.is_object())
  {
    for(auto item : cookies.items())
    {
      if(item.value().is_null())
      {
        j.erase(item.key());
      }
      else
      {
        j.merge_patch(nlohmann::json{{item.key(), item.value()}});
      }
    }
  }
  else
  {
    throw InvalidKeyError(std::string("expected object:") + cookies.dump());
  }
}

std::string PamHandshake::pam_input(const std::string & message,
                                    nlohmann::json & j,
                                    bool do_echo)
{
  std::string default_value;
  try
  {
    default_value = extract_default_value(message, j);
  }
  catch(const std::exception & ex)
  {
  }
  std::string answer;
  if(default_value.empty() || do_echo)
  {
    std::cout << message;
    if(!default_value.empty())
    {
      std::cout << "[" << default_value << "]";
    }
    std::getline(std::cin, answer);
  }
  if(answer.empty())
  {
    answer = default_value;
  }
  j[message] = {{"answer", answer},
                {"scrambled", false}};
  return answer;
}

std::string PamHandshake::pam_input_password(const std::string & message,
                                             nlohmann::json & j,
                                             bool do_echo)
{
  std::string default_value;
  try
  {
    default_value = extract_default_value(message, j);
  }
  catch(const std::exception & ex)
  {
  }
  std::string answer;
  if(default_value.empty() || do_echo)
  {
    std::cout << message;
    if(!default_value.empty())
    {
      std::cout << "[****]";
    }
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
  if(default_value.empty() || do_echo)
  {
    std::getline(std::cin, answer);
  }
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
  if(default_value.empty() || do_echo)
  {
    std::cout << std::endl << std::flush;
  }
  if(answer.empty())
  {
    answer = default_value;
  }
  if(answer.size() > MAX_PASSWORD_LEN)
  {
    answer.erase(MAX_PASSWORD_LEN);
  }
  char * pw = new char[answer.size() + 10];
  obfEncodeByKey(answer.c_str(),
                 OBF_KEY,
                 pw);
  j[message] = {{"answer", std::string(pw)},
                {"scrambled", true}};
  delete [] pw;
  return answer;
}

std::string PamHandshake::get_conversation_file()
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

void PamHandshake::save_conversation(std::ostream & ost,
                                     const nlohmann::json & json_conversation)
{
  ost << json_conversation;
}

void PamHandshake::save_conversation(const nlohmann::json & json_conversation, int VERBOSE_LEVEL)
{
  std::string file_name(get_conversation_file());
  PAM_CLIENT_LOG(PAMLOG_INFO, "SAVE conversation: " << file_name);
  std::ofstream file(file_name.c_str());
  if (file.is_open())
  {
    save_conversation(file, json_conversation);
    file.close();
  }
  else
  {
    throw std::runtime_error((std::string("cannot write to  file ") + file_name).c_str());
  }
}

nlohmann::json PamHandshake::load_conversation(std::istream & ist)
{
  nlohmann::json json_conversation;
  ist >> json_conversation;
  return json_conversation;
}

nlohmann::json PamHandshake::load_conversation(int VERBOSE_LEVEL)
{
  nlohmann::json json_conversation;
  std::string file_name(get_conversation_file());
  PAM_CLIENT_LOG(PAMLOG_INFO, "LOAD  conversation: " << file_name);
  std::ifstream file(file_name.c_str());
  if (file.is_open())
  {
    nlohmann::json json_conversation(load_conversation(file));
    file.close();
    return json_conversation;
  }
  else
  {
    return "{}"_json;
  }
}


  
