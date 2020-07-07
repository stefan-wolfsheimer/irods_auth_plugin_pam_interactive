#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include "pam_interactive_config.h"
#include "irods_kvp_string_parser.hpp"

using Message = PamHandshake::Message;
using ParseError = PamHandshake::ParseError;
using HttpError = PamHandshake::HttpError;
using StateError = PamHandshake::StateError;

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

TEST_CASE("Construct simple message", "[Message]")
{
  {
    // message with empty string
    Message m(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"}}));
    REQUIRE(m.getMessage() == "");
    REQUIRE(m.getUpdateKey() == "");
    REQUIRE(m.hasEcho());
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getAnswerMode() == Message::AnswerMode::Always);

  }
  {
    // message with empty string
    Message m(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"},
          {"MESSAGE", "hello"}}));
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getUpdateKey() == "hello");
    REQUIRE(m.hasEcho());
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getAnswerMode() == Message::AnswerMode::Always);
  }
}

TEST_CASE("Invalid json message", "[Message]")
{
  REQUIRE_THROWS_AS(Message(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"},
          {"MESSAGE", "{"}})),
    nlohmann::json::parse_error);
}

TEST_CASE("Construct complex message", "[Message]")
{
    Message m(irods::escaped_kvp_string(irods::kvp_map_t{
          {"CODE", "200"},
          {"STATE", "WAITING"},
          {"MESSAGE", R"({"echo":"hello", "update": "field", "ask": "never"})"}}));
    REQUIRE(m.getMessage() == "hello");
    REQUIRE(m.getUpdateKey() == "field");
    REQUIRE(m.hasEcho());
    REQUIRE(m.getState() == Message::State::Waiting);
    REQUIRE(m.getAnswerMode() == Message::AnswerMode::Never);
    REQUIRE(m.getCookies().dump() == "null");
}

TEST_CASE("Construct complex message with cookie", "[Message]")
{
  nlohmann::json json_msg = nlohmann::json::object({
      {"echo", "hello"},
      {"update", "field"},
      {"ask", "never"},
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
  Message m(irods::escaped_kvp_string(irods::kvp_map_t{
        {"CODE", "200"},
        {"STATE", "WAITING"},
        {"MESSAGE", json_msg.dump()}}));
  REQUIRE(m.getMessage() == "hello");
  REQUIRE(m.getUpdateKey() == "field");
  REQUIRE(m.hasEcho());
  REQUIRE(m.getState() == Message::State::Waiting);
  REQUIRE(m.getAnswerMode() == Message::AnswerMode::Never);
  REQUIRE(m.getCookies().dump() != "null");

  nlohmann::json doc = {
    {"k2", nlohmann::json::object({{"value", "v0"}})},
    {"kx", nlohmann::json::object({{"value", "vx"}})},
    {"k3", nlohmann::json::object({{"value", "v3"}})}};
  PamHandshake::update_cookies(doc, m.getCookies());
  REQUIRE(doc.find("kx") == doc.end());
  REQUIRE(doc["k1"]["value"].get<std::string>() == "v1");
  REQUIRE(doc["k2"]["value"].get<std::string>() == "v2");
  REQUIRE(doc["k2"]["valid_until"].get<std::string>() == "2020-12-31 00:00");
  REQUIRE(doc["k3"]["value"].get<std::string>() == "v3");
}
