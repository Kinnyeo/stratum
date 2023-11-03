#include "stratum/hal/lib/nikss/nikss_wrapper.h"

#include <memory>
#include <set>
#include <utility>
#include <fstream>
#include <string>
#include <iostream>

#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"
#include "stratum/glue/status/status.h"
#include "stratum/lib/utils.h"
#include "stratum/lib/macros.h"

extern "C" {
#include "nikss/nikss.h"
#include "nikss/nikss_pipeline.h"
}

// A macro for simplify checking the return value of NIKSS API.
// For now, we always return ERR_INTERNAL.
#define RETURN_IF_NIKSS_ERROR(expr)                                                \
  do {                                                                       \
    /* Using _status below to avoid capture problems if expr is "status". */ \
    const int __ret = (expr);                                   \
    if (__ret != 0) {                                 \
      return MAKE_ERROR(ERR_INTERNAL) << "Return Error: "                        \
                                      << #expr << " failed with code " << __ret; \
    }                                                                            \
  } while (0)


namespace stratum {
namespace hal {
namespace nikss {

NikssWrapper* NikssWrapper::singleton_ = nullptr;
ABSL_CONST_INIT absl::Mutex NikssWrapper::init_lock_(absl::kConstInit);

NikssWrapper::NikssWrapper() {}

::util::Status NikssWrapper::AddPort(int pipeline_id,
                                     const std::string& port_name) {
  auto ctx = absl::make_unique<nikss_context_t>();
  nikss_context_init(ctx.get());
  nikss_context_set_pipeline(ctx.get(), static_cast<nikss_pipeline_id_t>(pipeline_id));

  int port_id = -1;
  LOG(INFO) << "Adding port " << port_name << " to pipeline " << pipeline_id << ".";
  RETURN_IF_NIKSS_ERROR(nikss_pipeline_add_port(ctx.get(), port_name.c_str(), &port_id));
  LOG(INFO) << "Port added with port_id=" << port_id << ".";
  nikss_context_free(ctx.get());
  
  return ::util::OkStatus();
}

::util::Status NikssWrapper::DelPort(int pipeline_id,
                                     const std::string& port_name) {
  auto ctx = absl::make_unique<nikss_context_t>();
  nikss_context_init(ctx.get());
  nikss_context_set_pipeline(ctx.get(), static_cast<nikss_pipeline_id_t>(pipeline_id));

  RETURN_IF_NIKSS_ERROR(nikss_pipeline_del_port(ctx.get(), port_name.c_str()));

  nikss_context_free(ctx.get());
  
  return ::util::OkStatus();
}

::util::Status NikssWrapper::AddPipeline(int pipeline_id,
                                         const std::string bpf_obj) {
  std::string tmp_filepath = "/etc/stratum/bpf.o";
  // FIXME: nikss currently doesn't support loading BPF programs from memory.
  //  So, we save it to the disk first and let NIKSS load it from the disk.
  RETURN_IF_ERROR(WriteStringToFile(bpf_obj, tmp_filepath));

  auto ctx = absl::make_unique<nikss_context_t>();
  nikss_context_init(ctx.get());
  nikss_context_set_pipeline(ctx.get(), static_cast<nikss_pipeline_id_t>(pipeline_id));
  if (nikss_pipeline_exists(ctx.get())) {
    LOG(INFO) << "NIKSS pipeline already exists, re-pushing is not supported yet.";
    return ::util::OkStatus();
  }

  RETURN_IF_NIKSS_ERROR(nikss_pipeline_load(ctx.get(), tmp_filepath.c_str()));
  
  RemoveFile(tmp_filepath);

  nikss_context_free(ctx.get());

  return ::util::OkStatus();
}

std::string NikssWrapper::ConvertToNikssName(std::string input_name){
    std::replace(input_name.begin(), input_name.end(), '.', '_');
    return input_name;
}

std::string NikssWrapper::SwapBytesOrder(std::string value){
    std::reverse(value.begin(), value.end()); 
    return value;
}

::util::Status NikssWrapper::ContextInit(
    nikss_context_t* nikss_ctx,
    nikss_table_entry_t* entry,
    nikss_table_entry_ctx_t* entry_ctx,
    nikss_action_t* action_ctx,
    int node_id, std::string name){

    nikss_context_init(nikss_ctx);
    nikss_context_set_pipeline(nikss_ctx, static_cast<nikss_pipeline_id_t>(node_id));
    nikss_table_entry_init(entry);
    nikss_table_entry_ctx_init(entry_ctx);
    std::string nikss_name = ConvertToNikssName(name);
    nikss_table_entry_ctx_tblname(nikss_ctx, entry_ctx, nikss_name.c_str());
    nikss_action_init(action_ctx);

    return ::util::OkStatus();
}

::util::Status NikssWrapper::AddMatchesToEntry(
    const ::p4::v1::TableEntry& request,
    const ::p4::config::v1::Table table,
    nikss_table_entry_t* entry){

    // Finding matches from request in p4info file
    bool ternary_key_exists = 0;
    for (const auto& expected_match : table.match_fields()){
      for (auto match : request.match()){
        if (expected_match.id() == match.field_id()){

          nikss_match_key_t mk;
          nikss_matchkey_init(&mk);
          std::string value;

          switch (expected_match.match_type()){
            case ::p4::config::v1::MatchField::EXACT: {
              auto exact_m = match.exact();
              value = exact_m.value();
              LOG(INFO) << "Found exact match with name: " << expected_match.name()
                        << " and value: " << value;
              nikss_matchkey_type(&mk, NIKSS_EXACT);
              break;
            }
            case ::p4::config::v1::MatchField::TERNARY: {
              ternary_key_exists = 1;
              auto ternary_m = match.ternary();
              value = ternary_m.value();
              LOG(INFO) << "Found ternary match with name: " << expected_match.name()
                        << ", value: " << value << " and mask: " << ternary_m.mask();
              nikss_matchkey_type(&mk, NIKSS_TERNARY);
              nikss_matchkey_mask(&mk, SwapBytesOrder(ternary_m.mask()).c_str(), ternary_m.mask().length()); //errory
              break;
            }
            case ::p4::config::v1::MatchField::LPM: {
              auto lpm_m = match.lpm();
              value = lpm_m.value();
              LOG(INFO) << "Found LPM match with name: " << expected_match.name()
                        << ", value: " << value << " and prefix length: " << lpm_m.prefix_len();
              nikss_matchkey_type(&mk, NIKSS_LPM);
              nikss_matchkey_prefix_len(&mk, lpm_m.prefix_len());
              break;
            }
            default: {
              return MAKE_ERROR(ERR_INVALID_PARAM) << "RANGE match key not supported yet!";
            }
          }
          
          value = SwapBytesOrder(value);
          int error_code = nikss_matchkey_data(&mk, value.c_str(), value.length());
          if (error_code != NO_ERROR){
            return MAKE_ERROR(ERR_INTERNAL) << "Adding data to key failed!";
          }

          error_code = nikss_table_entry_matchkey(entry, &mk);
          nikss_matchkey_free(&mk);
          if (error_code != NO_ERROR){
            return MAKE_ERROR(ERR_INTERNAL) << "Adding key to table entry failed!";
          }
          break;
        }
      }
    }
    auto priority = request.priority();
    if (!ternary_key_exists && priority != 0){
      return MAKE_ERROR(ERR_INVALID_PARAM) << "Priority provided without TERNARY key!";
    } else if (ternary_key_exists && priority == 0){
      return MAKE_ERROR(ERR_INVALID_PARAM) << "Priority not provided with TERNARY key!";
    }

    return ::util::OkStatus();
}

::util::Status NikssWrapper::AddActionsToEntry(
    const ::p4::v1::TableEntry& request,
    const ::p4::config::v1::Table table,
    const ::p4::config::v1::Action action,
    nikss_action_t* action_ctx,
    nikss_table_entry_ctx_t* entry_ctx,
    nikss_table_entry_t* entry){

    // Finding actions from request in p4info file
    auto action_id = request.action().action().action_id();
    for (const auto& p4info_action : table.action_refs()){
      if (action_id == p4info_action.id()){
        std::string action_name = ConvertToNikssName(action.preamble().name());
        LOG(INFO) << "Found action with name: " << action_name;

        int action_ctx_id = nikss_table_get_action_id_by_name(entry_ctx, action_name.c_str());
        nikss_action_set_id(action_ctx, action_ctx_id);
        
        bool param_exists = 0;
        for (auto param : action.params()) {
          int param_id = param.id();
          for (auto request_param : request.action().action().params()){
            if (request_param.param_id() == param_id){
              LOG(INFO) << "Param value: " << request_param.value();

              auto value = SwapBytesOrder(request_param.value());
              LOG(INFO) << "length: "<< value.length();
              nikss_action_param_t param;

              int error_code = nikss_action_param_create(&param, value.c_str(), value.length());
              if (error_code != NO_ERROR){
                return MAKE_ERROR(ERR_INTERNAL) << "Creating action parameter failed!";
                nikss_action_param_free(&param);
              }

              error_code = nikss_action_param(action_ctx, &param);
              nikss_action_param_free(&param);
              if (error_code != NO_ERROR){
                return MAKE_ERROR(ERR_INTERNAL) << "Setting action parameter failed!";
              }
              param_exists = 1;
              break;
            }
          }

          if (!param_exists){
            return MAKE_ERROR(ERR_INVALID_PARAM) << "Parameter not found!";
          }
        }
        break;
      }
    }
    // Add action to entry
    nikss_table_entry_action(entry, action_ctx);
    return ::util::OkStatus();
}

::util::Status NikssWrapper::PushTableEntry(
    const ::p4::v1::Update::Type type,
    const ::p4::config::v1::Table table,
    nikss_table_entry_ctx_t* entry_ctx,
    nikss_table_entry_t* entry){
    
    switch (type) {
      case ::p4::v1::Update::INSERT: {
        int error_code = nikss_table_entry_add(entry_ctx, entry);
        if (error_code != NO_ERROR){
          return MAKE_ERROR(ERR_INTERNAL) << "Inserting table entry failed!";
        } else {
          auto name = table.preamble().name();
          LOG(INFO) << "Successfully added table " << ConvertToNikssName(name);
        }
        break;
      }
      case ::p4::v1::Update::MODIFY: {
        int error_code = nikss_table_entry_update(entry_ctx, entry);
        if (error_code != NO_ERROR){
          return MAKE_ERROR(ERR_INTERNAL) << "Modifying table entry failed!";
        } else {
          auto name = table.preamble().name();
          LOG(INFO) << "Successfully modified table " << ConvertToNikssName(name);
        }
        break;
      }
      default: {
        return MAKE_ERROR(ERR_INTERNAL)
               << "Unsupported update type: " << type << ".";
      }
    }
    return ::util::OkStatus();
}

::util::Status NikssWrapper::Cleanup(
    nikss_context_t* nikss_ctx,
    nikss_table_entry_t* entry,
    nikss_table_entry_ctx_t* entry_ctx,
    nikss_action_t* action_ctx){

    // Cleanup
    nikss_context_free(nikss_ctx);
    nikss_table_entry_free(entry);
    nikss_table_entry_ctx_free(entry_ctx);
    nikss_action_free(action_ctx);

    return ::util::OkStatus();
}

NikssWrapper* NikssWrapper::CreateSingleton() {
  absl::WriterMutexLock l(&init_lock_);
  if (!singleton_) {
    singleton_ = new NikssWrapper();
  }

  return singleton_;
}

}  // namespace nikss
}  // namespace hal
}  // namespace stratum
