#include <stdexcept>
#include <iostream>
#include <sstream>
#include <thread>
#include <string.h>
#include <security/pam_appl.h>
#include <unistd.h>
#include "ipam_client.h"
#include "pam_conversation.h"
#define MSG_PAM_CONV 1
#define MSG_PAM_ANSWER 2
#define MSG_DONE 3
#define MSG_ERROR 4

using namespace PamHandshake;


PamAuthCheckException::PamAuthCheckException(int _pam_code,
                                             std::string _msg) :
  std::runtime_error(_msg), msg(_msg), pam_code(_pam_code)
{}

int PamAuthCheckException::getPamCode() const
{
  return pam_code;
}

std::string PamAuthCheckException::getMessage() const
{
  return msg;
}

int PamHandshake::pam_conversation(int n,
                                   const struct pam_message **msg,
                                   struct pam_response **resp,
                                   void *data)
{
  auto pamClient = static_cast<IPamClient*>(data);
  if(!pamClient || pamClient->canceled())
  {
    return PAM_CONV_ERR;
  }
  struct pam_response *aresp;
  if (n <= 0 || n > PAM_MAX_NUM_MSG)
  {
    return PAM_CONV_ERR;
  }
  if ((aresp = (pam_response*)calloc(n, sizeof *aresp)) == NULL)
  {
    return PAM_BUF_ERR;
  }
  try
  {
    for(int i = 0; i < n; ++i)
    {
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;
      switch (msg[i]->msg_style)
      {
      case PAM_PROMPT_ECHO_OFF:
        pamClient->promptEchoOff(msg[i]->msg, &aresp[i]);
        break;
      case PAM_PROMPT_ECHO_ON:
        pamClient->promptEchoOn(msg[i]->msg, &aresp[i]);
        break;
      case PAM_ERROR_MSG:
        pamClient->errorMsg(msg[i]->msg);
        break;
      case PAM_TEXT_INFO:
        pamClient->textInfo(msg[i]->msg);
        break;
      default:
        throw std::invalid_argument(std::string("invalid PAM message style ") +
                                    std::to_string(msg[i]->msg_style));
      }
    }
  }
  catch(std::exception & ex)
  {
    // cleanup
    for (int i = 0; i < n; ++i)
    {
      if (aresp[i].resp != NULL)
      {
        memset(aresp[i].resp, 0, strlen(aresp[i].resp));
        free(aresp[i].resp);
      }
    }
    memset(aresp, 0, n * sizeof(*aresp));
    *resp = NULL;
    return PAM_CONV_ERR;
  }
  *resp = aresp;
  if(pamClient->canceled())
  {
    return PAM_CONV_ERR;
  }
  return PAM_SUCCESS;
}

bool PamHandshake::pam_auth_check(const std::string & pam_service,
                                  PamHandshake::IPamClient & client,
                                  bool verbose)
{
  pam_handle_t *pamh = nullptr;
  pam_conv conv = { PamHandshake::pam_conversation, &client };
  const int retval_pam_start = pam_start(pam_service.c_str(),
                                         nullptr,
                                         &conv,
                                         &pamh );
  if(verbose)
  {
    std::cout << "pam_start: " << retval_pam_start << std::endl;
  }
  if(retval_pam_start != PAM_SUCCESS)
  {
    throw std::runtime_error("pam_start_error");
  }
  const int retval_pam_authenticate = pam_authenticate( pamh, 0 );
  if(verbose)
  {
    if(retval_pam_authenticate == PAM_SUCCESS)
    {
      std::cout << "pam_authenticate: PAM_SUCCESS" << std::endl;
    }
    else
    {
      std::cout << "pam_authenticate: " << retval_pam_authenticate
                << ": "
                << pam_strerror(pamh, retval_pam_authenticate)
                << std::endl;
    }
  }
  if(pam_end( pamh, retval_pam_authenticate ) != PAM_SUCCESS)
  {
    pamh = NULL;
    throw std::runtime_error("irodsPamAuthCheck: failed to release authenticator");
  }
  if(retval_pam_authenticate != PAM_AUTH_ERR &&
     retval_pam_authenticate != PAM_SUCCESS &&
     retval_pam_authenticate != PAM_USER_UNKNOWN)
  {
    std::stringstream ss;
    ss << "pam_authenticate: " << retval_pam_authenticate
       << ": "
       << pam_strerror(pamh, retval_pam_authenticate)
       << std::endl;
    throw PamAuthCheckException(retval_pam_authenticate, ss.str());
  }
  // indicate success (valid username and password) or not
  return retval_pam_authenticate == PAM_SUCCESS;
}

bool PamHandshake::pam_auth_check_wrapper(const std::string & application,
                                         const std::string & pam_service,
                                         PamHandshake::IPamClient & client,
                                         bool verbose)
{
  int p_read[2];
  int p_write[2];
  if(pipe(p_read))
  {
    throw std::runtime_error("cannot create pipe");
  }
  if(pipe(p_write))
  {
    throw std::runtime_error("cannot create pipe");
  }
  pid_t child_pid = fork();
  if(child_pid < 0)
  {
    throw std::runtime_error("fork failed");
  }
  else if(child_pid == 0)
  {
    close(p_write[0]);
    close(p_read[1]);
    dup2(p_write[1], STDOUT_FILENO);
    dup2(p_read[0], STDIN_FILENO);
    execl(application.c_str(), "--bin", "--stack", pam_service.c_str(), nullptr);
    exit(0);
  }
  else
  {
    close(p_write[1]);
    close(p_read[0]);
    int fd_read = p_write[0];
    int fd_write = p_read[1];
    int ret = 0;
    while(true)
    {
      std::string msg;
      std::pair<int, int> code = PamBinClient::readMessage(fd_read, msg);
      if(code.first == MSG_PAM_CONV)
      {
        if(code.second == PAM_PROMPT_ECHO_ON)
        {
          struct pam_response resp;
          client.promptEchoOn(msg.c_str(), &resp);
          PamBinClient::writeMessage(fd_write, MSG_PAM_ANSWER, 0, resp.resp);
        }
        else if(code.second == PAM_PROMPT_ECHO_OFF)
        {
          struct pam_response resp;
          client.promptEchoOff(msg.c_str(), &resp);
          PamBinClient::writeMessage(fd_write, MSG_PAM_ANSWER, 0, resp.resp);
        }
        else if(code.second == PAM_ERROR_MSG)
        {
          client.errorMsg(msg.c_str());
        }
        else if(code.second == PAM_TEXT_INFO)
        {
          client.textInfo(msg.c_str());
        }
        else
        {
          close(p_write[0]);
          close(p_read[1]);
          throw std::invalid_argument((std::string("invalid PAM message type ") + std::to_string(code.second)).c_str());
        }
      }
      else if(code.first == MSG_DONE)
      {
        close(p_write[0]);
        close(p_read[1]);
        return (bool)code.second;
      }
      else if(code.first == MSG_ERROR)
      {
        close(p_write[0]);
        close(p_read[1]);
        throw PamAuthCheckException(code.second, msg.c_str());
      }
      else
      {
        close(p_write[0]);
        close(p_read[1]);
        throw std::runtime_error(std::string("invalid status ") + std::to_string(code.first));
      }
    } // while true
    close(p_write[0]);
    close(p_read[1]);
    return ret;
  }
  return false;
}

void PamHandshake::pam_send_auth_result(bool result)
{
  PamBinClient::writeMessage(STDOUT_FILENO, MSG_DONE, result ? 1 : 0, "Authenticated");
}

void PamHandshake::pam_send_exception(const PamAuthCheckException & ex)
{
  PamBinClient::writeMessage(STDOUT_FILENO, MSG_ERROR, ex.getPamCode(), ex.getMessage().c_str());
}


void PamBinClient::promptEchoOn(const char * msg, pam_response_t * resp)
{
  std::string rmsg;
  writeMessage(STDOUT_FILENO, MSG_PAM_CONV, PAM_PROMPT_ECHO_ON, msg);
  resp->resp_retcode = readAnswerMessage(STDIN_FILENO, rmsg);
  resp->resp = strdup(rmsg.c_str());
}

void PamBinClient::promptEchoOff(const char * msg, pam_response_t * resp)
{
  std::string rmsg;
  writeMessage(STDOUT_FILENO, MSG_PAM_CONV, PAM_PROMPT_ECHO_OFF, msg);
  resp->resp_retcode = readAnswerMessage(STDIN_FILENO, rmsg);
  resp->resp = strdup(rmsg.c_str());
}

void PamBinClient::errorMsg(const char * msg)
{
  PamBinClient::writeMessage(STDOUT_FILENO, MSG_PAM_CONV, PAM_ERROR_MSG, msg);
}

void PamBinClient::textInfo(const char * msg)
{
  PamBinClient::writeMessage(STDOUT_FILENO, MSG_PAM_CONV, PAM_TEXT_INFO, msg);
}

bool PamBinClient::canceled()
{
  return false;
}

void PamBinClient::writeMessage(int fd, int state, int type, const char * msg)
{
  unsigned char bytes[6];
  uint32_t n = strlen(msg);
  bytes[0] = state;
  bytes[1] = type;
  bytes[2] = n & 0xFF;
  bytes[3] = (n >> 8) & 0xFF;
  bytes[4] = (n >> 16) & 0xFF;
  bytes[5] = (n >> 24) & 0xFF;
  write(fd, bytes, sizeof(bytes));
  write(fd, msg, n);
}

std::pair<int, int> PamBinClient::readMessage(int fd, std::string & msg)
{
#define MESSAGE_SIZE 6
  // read header
  unsigned char bytes[MESSAGE_SIZE];
  std::size_t bytes_read;
  std::size_t pos = 0;
  int state = 0;
  int type = 0;
  std::size_t n = 0;
  std::size_t i;
  while(pos < MESSAGE_SIZE)
  {
    bytes_read = read(fd, bytes, MESSAGE_SIZE - pos);
    for(i = 0; i < bytes_read; i++)
    {
      if(pos == 0)
      {
        state = bytes[i];
      }
      else if(pos == 1)
      {
        type = bytes[i];
      }
      else
      {
        int c = bytes[i];
        int shiftby = (pos-2)*8;
        n+= (c << shiftby);
      }
      pos++;
    }
    if(!bytes_read)
    {
      break;
    }
  }
  if(pos < MESSAGE_SIZE)
  {
    return std::make_pair(0, 0);
  }
  std::size_t rem = n;
  char buffer[255];
  do
  {
    if(rem < sizeof(buffer))
    {
      bytes_read = read(fd, buffer, rem);
    }
    else
    {
      bytes_read = read(fd, buffer, sizeof(buffer));
    }
    rem-= bytes_read;
    msg.append(buffer, bytes_read);
  }
  while(bytes_read);
  return std::make_pair(state, type);
#undef MESSAGE_SIZE
}

int PamBinClient::readAnswerMessage(int fd, std::string & msg)
{
  std::pair<int, int> p = readMessage(fd, msg);
  if(p.first != MSG_PAM_ANSWER)
  {
    throw std::runtime_error("expected PAM answer message");
  }
  return p.second;
}
