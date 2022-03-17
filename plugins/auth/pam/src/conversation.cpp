#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <json.hpp>
#include "getRodsEnv.h"
#include "authenticate.h"
#include "rodsErrorTable.h"
#include "message.h"
#include "conversation.h"

/////////////////////////////////////////////////////////////
//
// Conversation
//
/////////////////////////////////////////////////////////////
PamHandshake::Conversation::Conversation()
  : is_dirty(false), j("{}"_json)
{
}

PamHandshake::Conversation::Conversation(const nlohmann::json & rhs)
  : is_dirty(false), j(rhs)
{
}

PamHandshake::Conversation::Conversation(nlohmann::json && rhs)
  : is_dirty(false), j(std::move(rhs))
{
}

void PamHandshake::Conversation::load()
{
  std::string file_name(getConversationFile());
  PAM_CLIENT_LOG(PAMLOG_INFO, "LOAD  conversation: " << file_name);
  std::ifstream file(file_name.c_str());
  if (file.is_open())
  {
    load(file);
    file.close();
  }
}

void PamHandshake::Conversation::load(std::istream & ist)
{
  ist >> j;
}

void PamHandshake::Conversation::reset()
{
  j = "{}"_json;
}

void PamHandshake::Conversation::save(bool force)
{
  if(is_dirty || force)
  {
    std::string file_name(getConversationFile());
    PAM_CLIENT_LOG(PAMLOG_INFO, "SAVE conversation: " << file_name);
    std::ofstream file(file_name.c_str());
    if (file.is_open())
    {
      file << j;
      file.close();
    }
    else
    {
      throw std::runtime_error((std::string("cannot write to  file ") + file_name).c_str());
    }
  }
  is_dirty = false;
}

std::string PamHandshake::Conversation::dump() const
{
  std::stringstream ss;
  ss << j;
  return ss.str();
}

std::tuple<bool, std::string> PamHandshake::Conversation::getValue(const std::string & key) const
{
  //@todo decode value
  if(j.contains(key))
  {
    if(j[key].is_string())
    {
      return std::make_tuple(true, j[key].get<std::string>());
    }
    else if(j[key].is_object())
    {
      if(j[key].contains("value"))
      {
        return std::make_tuple(true, j[key]["value"].get<std::string>());
      }
    }
  }
  return std::make_tuple(false, "");
}

std::tuple<bool, std::string> PamHandshake::Conversation::getValidUntil(const std::string & key) const
{
  if(j.contains(key))
  {
    if(j[key].is_string())
    {
      return std::make_tuple(true, j[key].get<std::string>());
    }
    else if(j[key].is_object())
    {
      if(j[key].contains("valid_until"))
      {
        return std::make_tuple(true, j[key]["valid_until"].get<std::string>());
      }
    }
  }
  return std::make_tuple(false, "");
}

void PamHandshake::Conversation::setValue(const std::string & key,
                                          const std::string & value,
                                          const std::string & valid_until)
{
  if(valid_until.empty())
  {
    j[key] = nlohmann::json::object({
        {"value", value},
        {"scrambled", false}});
  }
  else
  {
    j[key] = nlohmann::json::object({
        {"value", value},
        {"scrambled", false},
        {"valid_until", valid_until}});
  }
}


bool PamHandshake::Conversation::isDirty() const
{
  return is_dirty;
}

std::string PamHandshake::Conversation::getConversationFile() const
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

