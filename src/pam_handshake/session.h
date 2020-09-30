#pragma once
#include "ipam_client.h"
#include <utility>
#include <condition_variable>
#include <thread>
#include <ctime>

namespace PamHandshake
{
  class Server;

  /**
   * PAM conversation session
   */
  class Session : public IPamClient
  {
  public:
    enum class State
      {
        Running,          // set from parent
        Ready,            // set from parent
        Waiting,          // set from worker
        WaitingPw,        // set from worker
        Answer,           // set from parent when answer is available
        Next,             // set from workder
        Error,            // set from parent
        Timeout,          // set from parent
        Authenticated,    // set from worker
        NotAuthenticated
      };
    // 0 -> Running               (parent)
    // Running -> Ready           (parent)
    // Ready -> Waiting           (worker)
    // Ready -> WaitingPw         (worker)
    // Ready -> Next              (worker)
    // Waiting -> Answer          (parent)
    // WaitingPw -> Answer        (parent)
    // Answer -> Next             (worker)
    // Next -> Ready              (parent)
    // Ready -> Authenticated     (worker)
    // Ready -> NotAuthenticated  (worker)

    Session(Server * _server);
    virtual ~Session();
    virtual void promptEchoOn(const char * msg, pam_response_t * resp) override;
    virtual void promptEchoOff(const char * msg, pam_response_t * resp) override;
    virtual void errorMsg(const char * msg) override;
    virtual void textInfo(const char * msg) override;
    virtual bool canceled() override;
    void cancel();
    static const char *  StateToString(const State & s);
    State getState() const;
    std::pair<State, std::string> pull(const char * answer,
                                       std::size_t len);
    void refresh();
    std::time_t getLastTime() const;



  private:
    mutable std::mutex mutex;
    Server * server;
    bool verbose;
    std::pair<State, std::string> nextMessage;
    std::string nextAnswer;
    std::condition_variable cv;
    std::time_t lastTime;
    std::thread t;

    void worker();
    inline void transition(State s, bool clean_string=true);
    inline bool statePredicate(State s);
  }; 

}
