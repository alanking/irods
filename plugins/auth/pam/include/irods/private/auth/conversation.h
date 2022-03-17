#pragma once
#include <json.hpp>
#include <iostream>
#include <stdexcept>
#include "irods_kvp_string_parser.hpp"

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
    void save(bool force=false);
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
