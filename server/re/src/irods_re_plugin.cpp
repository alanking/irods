#include "irods_re_plugin.hpp"
#include "region.h"
#include "irods_hashtable.h"
#include "irods_server_properties.hpp"
#include "irods_exception.hpp"
#include "irods_ms_plugin.hpp"
#include "irods_at_scope_exit.hpp"

#include <vector>

#include <boost/any.hpp>

#include "fmt/format.h"

int actionTableLookUp( irods::ms_table_entry& _entry, const char* _action );

namespace irods
{
    // extern variable for the re plugin globals
    std::unique_ptr<struct global_re_plugin_mgr> re_plugin_globals;

    void var_arg_to_list(std::list<boost::any>& _l) {
        (void) _l;
    }

    error list_to_var_arg(std::list<boost::any>& _l) {
        if(! _l.empty()) {
            return ERROR(-1, "arg list mismatch");
        } else {
            return SUCCESS();
        }
    }

    unpack::unpack(std::list<boost::any> &_l) : l_(_l) {};

    std::vector<re_pack_inp<default_re_ctx> > init_global_re_packs() {
        std::vector<re_pack_inp<default_re_ctx> > ret;
        const auto& re_plugin_configs = irods::get_server_property<const std::vector<boost::any>>(std::vector<std::string>{irods::CFG_PLUGIN_CONFIGURATION_KW, irods::PLUGIN_TYPE_RULE_ENGINE});
        for(const auto& el : re_plugin_configs ) {
            const auto& map = boost::any_cast<const std::unordered_map<std::string, boost::any>&>(el);
            ret.emplace_back(
                boost::any_cast<const std::string&> (map.at("instance_name")),
                boost::any_cast<const std::string&> (map.at("plugin_name")),
                UNIT);
        }
        return ret;
    }

    template class pluggable_rule_engine<default_re_ctx>;

    error convertToMsParam(boost::any& _in, msParam_t* _out)
    {
        if (_in.type() == typeid(std::string)) {
            fillStrInMsParam(_out, boost::any_cast<std::string>(_in).c_str());
        }
        else if (_in.type() == typeid(std::string*)) {
            delete boost::any_cast<std::string*>(_out);
            fillStrInMsParam(_out, boost::any_cast<std::string*>(_in)->c_str());
        }
        else if (_in.type() == typeid(msParam_t*)) {
            clearMsParam(_out, 1);
            // _out = 0xA
            replMsParam(boost::any_cast<msParam_t*>(_in), _out);
        }
        else {
            return ERROR(MICRO_SERVICE_OBJECT_TYPE_UNDEFINED, "cannot convert parameter");
        }

        return SUCCESS();
    } // convertToMsParam

    error convertFromMsParam(boost::any& _out, msParam_t* _in)
    {
        if (!_in->type) {
            return ERROR(MICRO_SERVICE_OBJECT_TYPE_UNDEFINED,
                         "type was null, cannot convert type");
        }

        if (std::string(_in->type).compare(STR_MS_T) == 0) {
            if (_out.type() == typeid(std::string*)) {
                delete boost::any_cast<std::string*>(_out);
                *(boost::any_cast<std::string*>(_out)) = std::string{reinterpret_cast<char*>(_in->inOutStruct)};
            }
            // TODO: what about std::string?

            return SUCCESS();
        }

        msParam_t* msp = boost::any_cast<msParam_t*>(_out);
        clearMsParam(msp, 1);

        replMsParam(_in, msp);

        return SUCCESS();
    } // convertFromMsParam

    error default_microservice_manager<default_ms_ctx>::exec_microservice_adapter(std::string msName,
                                                                                  default_ms_ctx rei,
                                                                                  std::list<boost::any>& l)
    {
        if(msName == "unsafe_ms_ctx") {
            default_ms_ctx* p;
            if(const auto err = list_to_var_arg(l, p); !err.ok()) {
                return err;
            }
            *p = rei;
            return SUCCESS();
        }

        const unsigned int arg_count = l.size();

        struct all_resources {
            all_resources() {
                //rNew = make_region(0, NULL);
                memset(msParams,0 ,sizeof(msParam_t[10]));
            }
            ~all_resources() {
                // Free msParams which came from the list
                for (auto* msp : myArgv) {
                    clearMsParam(msp, 1);
                }
                //region_free(rNew);
            }

            std::vector<msParam_t *> myArgv;
            //Region *rNew; // TODO: documentation!!
            msParam_t msParams[10];
        } ar;

        irods::ms_table_entry ms_entry;
        if (const auto index = actionTableLookUp(ms_entry, msName.c_str()); index < 0) {
            return ERROR(NO_MICROSERVICE_FOUND_ERR, fmt::format(
                         "[{}:{}] - no microservice found [name=[{}], ec=[{}]]",
                         __func__, __LINE__, msName, index));
        }

        int i = 0;
        for (auto& in : l) {
            auto* out = &(ar.msParams[i]);
            // Copy bufs from list into msParams
            // out = 0xA
            // ar.msParams[i] = 0xA
            if (const auto err = convertToMsParam(in, out); !err.ok()) {
                return err;
            }
            // ar.myArgv.at(i) = 0xA
            ar.myArgv.push_back(out);
            i++;
        }

        const unsigned int expected_arg_count = ms_entry.num_args();
        if (arg_count != expected_arg_count) {
            return ERROR(ACTION_ARG_COUNT_MISMATCH, fmt::format(
                         "[{}:{}] - arguments in: [{}]; arguments expected: [{}]",
                         __func__, __LINE__, arg_count, expected_arg_count));
        }

        if (const auto ec = ms_entry.call(rei, ar.myArgv); ec < 0) {
            return ERROR(ec, fmt::format(
                         "[{}:{}] - microservice execution failed; ec=[{}]",
                         __func__, __LINE__, ec));
        }

        i = 0;
        for (auto& out : l) {
            auto* in = ar.myArgv[i];
            // Copy bufs from msParams into list
            // TODO: ...which still has its items from the beginning
            // TODO: does boost::any free memory? I doubt it
            if (const auto err = convertFromMsParam(out, in); !err.ok()) {
                return err;
            }
            i++;
        }

        return SUCCESS();
    } // default_microservice_manager<default_ms_ctx>::exec_microservice_adapter
} // namespace irods
