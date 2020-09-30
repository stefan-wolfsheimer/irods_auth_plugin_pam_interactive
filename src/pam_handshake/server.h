#pragma once
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <map>
#include <vector>
#include <set>
#include "session.h"

namespace PamHandshake
{
  class Session;
  class Connection;

  class InvalidToken : public std::runtime_error
  {
  public:
    inline InvalidToken(const std::string & token)
      : runtime_error(std::string("invalid token: ") + token)
    {
    }
  };
  
  /**
   * Server that is listening on port or unix domain socket.
   */
  class Server : public std::enable_shared_from_this<Server>
  {
  public:
    friend class Connection;

    static std::shared_ptr<Server>  getInstance(const std::string & pam_stack_name="irods",
                                                const std::string & conversation_program="",
                                                std::size_t connection_pool_size=10,
                                                std::size_t connection_timeout=10000, // milliseconds
                                                std::size_t session_timeout=3600, // seconds
                                                bool _verbose=false);

    Server(const std::string & pam_stack_name,
           const std::string & conversation_program="",
           std::size_t connection_pool_size=10,
           std::size_t connection_timeout=10000, // milliseconds
           std::size_t session_timeout=3600, // seconds
           bool _verbose=false);

    ~Server();

    void setConversationProgram(const std::string & exe);
    std::string getConversationProgram() const;
    bool hasConversationProgram() const;

    /**
     * \param return true if server is in verbose mode
     */
    bool isVerbose() const;

    /**
     * \return name of the PAM stack in /etc/pam.d
     */
    const std::string getPamStackName() const;

    /**
     * Start the server
     */
    void run();
    void handle(std::shared_ptr<Connection> conn);

    std::string createSession();

    Session::State getState(const std::string & token);

    std::pair<Session::State, std::string> pull(const std::string & token,
                                                const std::string & content);
    
    void deleteSession(const std::string & token);


    std::string randomString(std::size_t len);
    void start_housekeeping();
  private:
    void init();
    void housekeeping();
    mutable std::mutex mutex;
    std::string pam_stack_name;
    std::string conversationProgram;
    std::string ip;
    std::string socketFile;
    std::string socketFileChgrp;

    bool verbose;
    bool running;
    int sockfd;
    std::random_device rd;
    std::mt19937 gen;


    struct timeval readTimeout;
    struct timeval writeTimeout;

    std::set<std::size_t> connections;
    std::size_t maxConnections;
    std::size_t connectionTimeout;
    std::size_t sessionTimeout;

    std::map<std::string, std::shared_ptr<Session>> sessions;
    std::vector<std::thread> threads;
    std::shared_ptr<std::thread> housekeeper;
  };

}
