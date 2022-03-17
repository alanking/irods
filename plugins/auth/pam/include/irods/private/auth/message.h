#pragma once
#include <json.hpp>
#include "irods_kvp_string_parser.hpp"
/**
   message types:
   ----------------------------
   case 1: {"echo": "msg",
            "context": "iinit"}
   Used for PAM info messages (where user is not challenged)

   context is optional:
   context=="iinit": default, only display message for iinit workflow
   context=="all": display message in iinit and other icommands

   ----------------------------
   case 2: {"echo": "msg",
            "ask": "user",
            "context": "iinit"}
   ask user for input and send answer back to server
   don't save user's answer locally.

   context is optional:
   context=="iinit": default, only challenge user for iinit workflow
   context=="all": challenge user for iinit and other icommands

   ----------------------------
   case 2b: {"echo": "msg",
             "ask": "user",
             "context": "iinit",
             "patch": {"key1": {"value": "v1", "valid_until": "2020-12-31"},
             "key2": {"value": "v2"}}
   same as case 1 and additional saves entries key1 and key2 on client side
   
   ----------------------------
   case 3: {"echo": "msg",
            "ask": "user",
            "context": "iinit",
            "key":  "key1"}
   ask user for input and send answer back to server
   save user's answer locally under key1.
   use value of key1 as default answer.

   context is optional:
   context=="iinit": default, only challenge user for iinit workflow
   context=="all": challenge user for iinit and other icommands

   a string that does not represent a json object is translated to
          {"echo": <str>,
           "ask": "user",
           "context": "iinit",
           "key":  <str>}
   ----------------------------
   case 3a: {"echo": "display message",
             "ask": "user",
             "key": "key",
             "context": "iinit",
             "valid_until": "yyyy-mm-dd"}
   ask user and save data locally under "key" with expiration date

   case 4: {"ask": "entry",
            "key": "key"}
   retrieve entry without user interaction
   retrieve empty value if cookie does not exist.

**/
namespace PamHandshake
{
  class Conversation;

  class MessageError : public std::runtime_error
  {
  public:
    inline MessageError(const std::string & msg) : std::runtime_error(msg) {}
  };

  class ParseError : public MessageError
  {
  public:
    inline ParseError(const std::string & msg)
      : MessageError(std::string("failed to parse message: ") + msg) {}
  };

  class HttpError : public MessageError
  {
  public:
    inline HttpError(const std::string & code = "")
      : MessageError(code.empty() ? std::string("No code") : (std::string("HTTP code: ") + code)) {}
  };

  class StateError : public MessageError
  {
  public:
    inline StateError(const std::string & state = "")
      : MessageError(state.empty() ? std::string("No state") : (std::string("invalid state: ") + state)) {}
  };

  class InvalidKeyError : public MessageError
  {
  public:
    inline InvalidKeyError(const std::string & key = "")
      : MessageError(std::string("invalid key:") + key) {}
  };

  class Message
  {
  public:
    enum class State
    {
      Running,
      Ready,
      Waiting,
      WaitingPw,
      Answer,
      Next,
      Error,
      Timeout,
      Authenticated,
      NotAuthenticated
    };


    enum class ResponseMode
    {
      User, Entry
    };

    enum class Context
    {
      IInit, ICommand, All
    };

    Message(const std::string & msg);

    inline State getState() const
    {
      return state;
    }

    inline const std::string & getMessage() const
    {
      return message;
    }

    inline const nlohmann::json & getKey() const
    {
      return key;
    }

    inline const nlohmann::json & getValidUntil() const
    {
      return valid_until;
    }

    inline ResponseMode getResponseMode() const
    {
      return answer_mode;
    }

    inline Context getContext() const
    {
      return context;
    }

    inline const nlohmann::json & getPatch() const
    {
      return patch;
    }

    /**
     * Update cookies in json configuration
     *
     * update / add /delete:
     * cookies = {key1: {value: <value>, valid_until: <datetime>},
                  key2: {value: <value>},
                  key3: null}
    */
    bool applyPatch(nlohmann::json & j) const;
    bool applyPatch(Conversation & c) const;

    /**
     * return true if current context is compatible with in_context
     *
     * in_context | getContext() | value
     * -----------+--------------|------
     * IInit      | IInit        | true
     * ICommand   | IInit        | false
     * IInit      | ICommand     | false
     * ICommand   | ICommand     | false
     * IInit      | All          | true
     * ICommand   | All          | true
     * All        | *            | true
     */
    bool isInContext(Context in_context=Context::All) const;
    
    /**
     * Display message
     */

    void echo(Context in_context=Context::All,
              std::ostream & ost=std::cout) const;
    /**
     * Read input from user.
     */
    std::tuple<bool, std::string> input(nlohmann::json & j,
                                        Context in_context=Context::All,
                                        std::istream & ist=std::cin,
                                        std::ostream & ost=std::cout) const;
    std::string input(Conversation & c,
                      Context in_context=Context::All,
                      std::istream & ist=std::cin,
                      std::ostream & ost=std::cout) const;
    std::tuple<bool, std::string> input_password(nlohmann::json & j,
                                                 Context in_context=Context::All,
                                                 std::istream & ist=std::cin,
                                                 std::ostream & ost=std::cout) const;
    std::string input_password(Conversation & c,
                               Context in_context=Context::All,
                               std::istream & ist=std::cin,
                               std::ostream & ost=std::cout) const;



  private:
    void parseJson();
    std::pair<bool, std::string> extractDefaultValue(const std::string & key,
                                                     const nlohmann::json & j) const;
    bool needUpdateInput(const nlohmann::json & j,
                         const std::string & k,
                         const std::string & a) const;
    irods::kvp_map_t kvp;
    State state;
    std::string message;
    nlohmann::json key;
    nlohmann::json valid_until;
    ResponseMode answer_mode;
    Context context;
    nlohmann::json patch;
  };
}
