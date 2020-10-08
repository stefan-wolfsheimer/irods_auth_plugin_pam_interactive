#include <catch.hpp>
#include <security/pam_appl.h>
#include <vector>
#include <utility>
#include <string.h>
#include <stdlib.h>
#include "pam_handshake/pam_conversation.h"
#include "pam_handshake/ipam_client.h"


class PamClientMockup : public PamHandshake::IPamClient
{
public:
  std::vector<std::pair<int, std::string>> results;

  virtual void promptEchoOn(const char * msg, pam_response_t * resp) override
  {
    resp->resp = strdup("on");
    results.push_back(std::make_pair<int, std::string>(PAM_PROMPT_ECHO_ON, msg));
  }

  virtual void promptEchoOff(const char * msg, pam_response_t * resp)  override
  {
    resp->resp = strdup("off");
    results.push_back(std::make_pair<int, std::string>(PAM_PROMPT_ECHO_OFF, msg));
  }

  virtual void errorMsg(const char * msg)  override
  {
    results.push_back(std::make_pair<int, std::string>(PAM_ERROR_MSG, msg));
  }

  virtual void textInfo(const char * msg) override
  {
    results.push_back(std::make_pair<int, std::string>(PAM_TEXT_INFO, msg));
  }
};


TEST_CASE("pam_conversation", "[PAM]")
{
  const struct pam_message msg0 = { .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "msg0" };
  const struct pam_message msg1 = { .msg_style = PAM_PROMPT_ECHO_ON,  .msg = "msg1" };
  const struct pam_message msg2 = { .msg_style = PAM_ERROR_MSG,       .msg = "msg2" };
  const struct pam_message msg3 = { .msg_style = PAM_TEXT_INFO,       .msg = "msg3" };
  const struct pam_message msg4 = { .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "msg4" };
  const struct pam_message* msg[] = { &msg0, &msg1, &msg2, &msg3, &msg4 };
  struct pam_response *resp = nullptr;
  int n = sizeof(msg) / sizeof(void*);
  REQUIRE(PamHandshake::pam_conversation(n,
                                         (const struct pam_message**) &msg,
                                         &resp,
                                         nullptr) == PAM_CONV_ERR);
  REQUIRE_FALSE(resp);
  PamClientMockup client;
  REQUIRE(PamHandshake::pam_conversation(n,
                                         (const struct pam_message**) &msg,
                                         &resp,
                                         &client) == PAM_SUCCESS);
  REQUIRE(client.results == std::vector<std::pair<int, std::string>>{
      { PAM_PROMPT_ECHO_OFF, "msg0" },
      { PAM_PROMPT_ECHO_ON,  "msg1" },
      { PAM_ERROR_MSG,       "msg2" },
      { PAM_TEXT_INFO,       "msg3" },
      { PAM_PROMPT_ECHO_OFF, "msg4" }});
  REQUIRE(resp[0].resp == std::string("off"));
  REQUIRE(resp[1].resp == std::string("on"));
  REQUIRE_FALSE(resp[2].resp);
  REQUIRE_FALSE(resp[3].resp);
  REQUIRE(resp[4].resp == std::string("off"));
  for(int i = 0; i < n; i++)
  {
    if(resp[i].resp)
    {
      free(resp[i].resp);
    }
  }
  free(resp);
}
