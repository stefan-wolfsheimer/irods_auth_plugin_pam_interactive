#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include "pam_interactive_config.h"
#include "irods_kvp_string_parser.hpp"
#include <sstream>

using Message = PamHandshake::Message;
using Conversation = PamHandshake::Conversation;
using ParseError = PamHandshake::ParseError;
using HttpError = PamHandshake::HttpError;
using StateError = PamHandshake::StateError;

// expected failures
TEST_CASE("Message construction failed", "[Message]")
{
  REQUIRE_THROWS_AS(Message("invalid message"), ParseError);
  REQUIRE_THROWS_AS(Message(irods::escaped_kvp_string(irods::kvp_map_t{{
            "KEY",
            "VALUE"}})), HttpError);
  REQUIRE_THROWS_AS(Message(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "500"}})), HttpError);
  REQUIRE_THROWS_AS(Message(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"}})), StateError);
  REQUIRE_THROWS_AS(Message(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "__some_state__"}})), StateError);
}

TEST_CASE("Invalid json message", "[Message]")
{
  Conversation conv;
  REQUIRE_THROWS_AS(Message(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"},
          {"MESSAGE", "{"}})),
    nlohmann::json::parse_error);
}

////////////////////////////////////////////////
// expected succeeds
////////////////////////////////////////////////
TEST_CASE("Simple conversation without echo", "[Message]")
{
  Conversation conv;
  Message m(irods::escaped_kvp_string(irods::kvp_map_t{
        {"CODE", "200"},
        {"STATE", "WAITING"}}));
  REQUIRE(m.getMessage() == "");
  REQUIRE(m.getKey() == "null"_json);
  REQUIRE(m.getState() == Message::State::Waiting);
  REQUIRE(m.getResponseMode() == Message::ResponseMode::User);
  std::stringstream ist("some_value");
  std::stringstream ost;
  REQUIRE(m.input(conv, true, ist, ost) == "some_value");
  REQUIRE_FALSE(conv.isDirty());
  REQUIRE(conv.getValue("hello") == std::make_tuple(false, std::string("")));
}

TEST_CASE("Simple conversation with echo", "[Message]")
{
  std::string msg_str = irods::escaped_kvp_string(irods::kvp_map_t{
      {"CODE", "200"},
      {"STATE", "WAITING"},
      {"MESSAGE", "hello"}});
  Conversation conv;
  {
    Message m(msg_str);
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getKey().get<std::string>() == "hello");
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::User);
    std::stringstream ist("some_value");
    std::stringstream ost;
    REQUIRE(m.input(conv, true, ist, ost) == "some_value");
  }
  {
    REQUIRE(conv.isDirty());
    REQUIRE(conv.getValue("hello") == std::make_tuple(true, std::string("some_value")));
  }
  // overwrite value
  {
    Message m(msg_str);
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getKey().get<std::string>() == "hello");
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::User);
    std::stringstream ist("some_value2");
    std::stringstream ost;
    REQUIRE(m.input(conv, true, ist, ost) == "some_value2");
  }
  {
    REQUIRE(conv.isDirty());
    REQUIRE(conv.getValue("hello") == std::make_tuple(true, std::string("some_value2")));
  }
  // additional value
  {
    std::string msg_str2(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"},
          {"MESSAGE", "hello2"}}));
    Message m(msg_str2);
    REQUIRE(m.getMessage() == "hello2");
    REQUIRE(m.getKey().get<std::string>() == "hello2");
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::User);
    std::stringstream ist("some_value_for_hello2");
    std::stringstream ost;
    REQUIRE(m.input(conv, true, ist, ost) == "some_value_for_hello2");
  }
  {
    REQUIRE(conv.isDirty());
    REQUIRE(conv.getValue("hello") == std::make_tuple(true, std::string("some_value2")));
    REQUIRE(conv.getValue("hello2") == std::make_tuple(true, std::string("some_value_for_hello2")));
  }
}

TEST_CASE("Json message", "[Message]")
{
  Conversation conv;
  std::string msg_str = irods::escaped_kvp_string(irods::kvp_map_t{
        {"CODE", "200"},
        {"STATE", "WAITING"},
        {"MESSAGE", R"({"echo":"hello", "ask": "entry"})"}});
  Message m(msg_str);
  REQUIRE(m.getMessage() == "hello");
  REQUIRE(m.getKey().is_null());
  REQUIRE(m.getState() == Message::State::Waiting);
  REQUIRE(m.getResponseMode() == Message::ResponseMode::Entry);
  REQUIRE(m.getPatch().is_null());
  // user value never ask because Message::ResponseMode::Entry
  std::stringstream ist("some_value2");
  std::stringstream ost;
  REQUIRE(m.input(conv, true, ist, ost) == "");
}

TEST_CASE("Complex message with key", "[Message]")
{
  Conversation conv;
  std::string msg_str(irods::escaped_kvp_string(irods::kvp_map_t{
        {"CODE", "200"},
        {"STATE", "WAITING"},
        {"MESSAGE", R"({"echo":"hello", "key": "field", "ask": "entry"})"}}));
  {
    Message m(msg_str);
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getKey().get<std::string>() == "field");
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::Entry);
    REQUIRE(m.getPatch().is_null());
    // user value never ask because Message::ResponseMode::Entry
    std::stringstream ist("some_value2");
    std::stringstream ost;
    REQUIRE(m.input(conv, true, ist, ost) == "");
    REQUIRE(ost.str() == "");
  }
  REQUIRE_FALSE(conv.isDirty());
  // never updated
  REQUIRE(conv.getValue("field") == std::make_tuple(false, std::string("")));
  conv.setValue("field", "value");
  {
    Message m(msg_str);
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getKey().get<std::string>() == "field");
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::Entry);
    REQUIRE(m.getPatch().is_null());
    // user value never ask because Message::ResponseMode::Entry
    std::stringstream ist("some_value2");
    std::stringstream ost;
    REQUIRE(m.input(conv, true, ist, ost) == "value");
    REQUIRE(ost.str() == "");
  }
  REQUIRE_FALSE(conv.isDirty());
}

TEST_CASE("Complex message with non-string values", "[Message]")
{
  Conversation conv("{\"b\":{\"value\": true}, \"i\":{\"value\": 1}}"_json);
  std::map<std::string, std::string> fields({{"b", "true"}, {"i", "1"}});
  for(auto & p : fields)
  {
    std::string msg_str(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"},
          {"MESSAGE", std::string("{\"key\":\"") + p.first + std::string("\",\"ask\": \"entry\"}")}}));
    Message m(msg_str);
    REQUIRE(m.getKey().get<std::string>() == p.first);
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::Entry);
    REQUIRE(m.getPatch().is_null());
    // user value never ask because Message::ResponseMode::Entry
    std::stringstream ist;
    std::stringstream ost;
    REQUIRE(m.input(conv, true, ist, ost) == p.second);
    REQUIRE(ost.str() == "");
  }
}


TEST_CASE("Message with patch", "[Message]")
{
  Conversation conv(nlohmann::json::object({
        {"k2", nlohmann::json::object({{"value", "v0"}})},
        {"kx", nlohmann::json::object({{"value", "vx"}})},
        {"k3", nlohmann::json::object({{"value", "v3"}})}}));
  REQUIRE(conv.getValue("kx") == std::make_tuple(true, std::string("vx")));
  REQUIRE(conv.getValidUntil("kx") == std::make_tuple(false, std::string("")));
  nlohmann::json json_msg = nlohmann::json::object({
      {"echo", "hello"},
      {"key", "field"},
      {"ask", "entry"},
      {"patch",
          nlohmann::json::object({
            {"k1",
                nlohmann::json::object({{"value", "v1"}})},
            {"kx",
                nullptr},
            {"k2",
                nlohmann::json::object({
                  {"value", "v2"},
                  {"valid_until", "2020-12-31 00:00"}})}})}});
  std::string msg_str(irods::escaped_kvp_string(irods::kvp_map_t{
        {"CODE", "200"},
        {"STATE", "WAITING"},
        {"MESSAGE", json_msg.dump()}}));
  {
    Message m(msg_str);
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getKey().get<std::string>() == "field");
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getResponseMode() == Message::ResponseMode::Entry);
    REQUIRE_FALSE(m.getPatch().is_null());
    m.applyPatch(conv);
  }
  REQUIRE(conv.isDirty());
  // removed entry
  REQUIRE(conv.getValue("kx") == std::make_tuple(false, std::string("")));
  REQUIRE(conv.getValidUntil("kx") == std::make_tuple(false, std::string("")));
  REQUIRE(conv.getValue("k1") == std::make_tuple(true, std::string("v1")));
  REQUIRE(conv.getValidUntil("k1") == std::make_tuple(false, std::string("")));
  REQUIRE(conv.getValue("k2") == std::make_tuple(true, std::string("v2")));
  REQUIRE(conv.getValidUntil("k2") == std::make_tuple(true, std::string("2020-12-31 00:00")));
  REQUIRE(conv.getValue("k3") == std::make_tuple(true, std::string("v3")));
  REQUIRE(conv.getValidUntil("k3") == std::make_tuple(false, std::string("")));
}
