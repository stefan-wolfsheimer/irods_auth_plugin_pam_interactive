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
}
