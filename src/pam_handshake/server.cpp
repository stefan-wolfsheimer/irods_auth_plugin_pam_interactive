#include <mutex>
#include "server.h"
#include "session.h"
#include <iostream>
#include <functional>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <signal.h>
#include <grp.h>

using namespace PamHandshake;

std::shared_ptr<PamHandshake::Server> Server::getInstance(const std::string & pam_stack_name,
                                                          const std::string & conversation_program,
                                                          std::size_t connection_pool_size,
                                                          std::size_t connection_timeout, // milliseconds
                                                          std::size_t session_timeout, // seconds
                                                          bool verbose)
{
  static std::mutex gmutex;
  static std::shared_ptr<Server> instance;
  std::lock_guard<std::mutex> guard(gmutex);
  if(!instance)
  {
    instance = std::make_shared<PamHandshake::Server>(pam_stack_name,
                                                      conversation_program,
                                                      connection_pool_size,
                                                      connection_timeout,
                                                      session_timeout,
                                                      verbose);
    instance->start_housekeeping();
    instance->run();
  }
  return instance;
}

Server::Server(const std::string & _pam_stack_name,
               const std::string & conversation_program,
               std::size_t connection_pool_size,
               std::size_t connection_timeout,
               std::size_t session_timeout,
               bool _verbose)
    : pam_stack_name(_pam_stack_name),
      conversationProgram(conversation_program),
      verbose(_verbose),
      running(false),
      gen(rd()),
      maxConnections(connection_pool_size),
      connectionTimeout(connection_timeout),
      sessionTimeout(session_timeout)
{
  init();
}

Server::~Server()
{
}

void Server::setConversationProgram(const std::string & exe)
{
  conversationProgram = exe;
}

std::string Server::getConversationProgram() const
{
  return conversationProgram;
}

bool Server::hasConversationProgram() const
{
  return !conversationProgram.empty();
}

void Server::init()
{
  readTimeout.tv_sec = 0;
  readTimeout.tv_usec = connectionTimeout * 1000;
  writeTimeout.tv_sec = 0;
  writeTimeout.tv_usec = connectionTimeout * 1000;
  if(verbose)
  {
    std::cout << "Server started using PAM stack /etc/pam.d/" << pam_stack_name << std::endl;
  }
}

void Server::start_housekeeping()
{
  auto self = shared_from_this();
  self->housekeeper = std::make_shared<std::thread>([self](){
      self->housekeeping();
  });
}

void Server::housekeeping()
{
  while(true)
  {
    std::this_thread::sleep_for(std::chrono::seconds(10));
    {
      std::vector<std::shared_ptr<Session>> to_be_canceled;
      {
        std::lock_guard<std::mutex> lock(mutex);
        if(verbose)
        {
          std::cout << "housekeeping " << std::endl;
        }
        auto itr = sessions.begin();
        while(itr != sessions.end())
        {
          auto next = itr;
          next++;
          if(std::difftime(std::time(nullptr), itr->second->getLastTime()) > sessionTimeout)
          {
            if(itr->second->getState() == Session::State::Error ||
               itr->second->getState() == Session::State::Timeout)
            {
              sessions.erase(itr);
            }
            else
            {
              to_be_canceled.push_back(itr->second);
            }
          }
          itr = next;
        }
      }//mutex
      for(auto s : to_be_canceled)
      {
        s->cancel();
      }
    }
  }
}

bool Server::isVerbose() const
{
  return verbose;
}

const std::string Server::getPamStackName() const
{
  return pam_stack_name;
}

void Server::run()
{
  running = true;
}

std::string Server::createSession()
{
  auto token = randomString(32);
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto session = std::make_shared<Session>(this);
    sessions.insert(std::make_pair(token, session));
  }
  return token;
}

Session::State Server::getState(const std::string & token)
{
  std::lock_guard<std::mutex> lock(mutex);
  auto itr = sessions.find(token);
  if(itr == sessions.end())
  {
    throw InvalidToken(token);
  }
  itr->second->refresh();
  return itr->second->getState();
}

std::pair<Session::State, std::string> Server::pull(const std::string & token,
                                                    const std::string & content)
{
  std::lock_guard<std::mutex> lock(mutex);
  auto itr = sessions.find(token);
  if(itr == sessions.end())
  {
    throw InvalidToken(token);
  }
  return itr->second->pull(content.c_str(),
                           content.size());
}

void Server::deleteSession(const std::string & token)
{
  std::lock_guard<std::mutex> lock(mutex);
  auto itr = sessions.find(token);
  if(itr == sessions.end())
  {
    throw InvalidToken(token);
  }
  itr->second->cancel();
  itr->second->refresh();
  sessions.erase(itr);
}

std::string Server::randomString(std::size_t len)
{
  std::uniform_int_distribution<> dis(0, 15);
  std::string str;
  int val;
  str.reserve(len);
  for(std::size_t j = 0; j < len; j++)
  {
    {
      std::lock_guard<std::mutex> lock(mutex);
      val = dis(gen);
    }
    str.push_back((char)(val < 10 ? ('0' + val) : ('a' + (val-10))));
  }
  return str;
}
