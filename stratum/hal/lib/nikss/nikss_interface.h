#ifndef STRATUM_HAL_LIB_NIKSS_NIKSS_INTERFACE_H_
#define STRATUM_HAL_LIB_NIKSS_NIKSS_INTERFACE_H_

#include "stratum/glue/status/status.h"
#include "stratum/glue/status/statusor.h"
#include "stratum/glue/integral_types.h"
#include "p4/v1/p4runtime.pb.h"
#include "nikss/nikss.h"

namespace stratum {
namespace hal {
namespace nikss {

class NikssInterface {
 public:
  
  // Add and initialize a NIKSS pipeline. The pipeline will be loaded
  // into the Linux eBPF subsystem. Can be used to re-initialize an existing device.
  virtual ::util::Status AddPipeline(int pipeline_id,
                                     const std::string filepath) = 0;

  // Add a new port with the given parameters.
  virtual ::util::Status AddPort(int pipeline_id, const std::string& port_name) = 0;

  // Init Nikss Contexts.
  virtual ::util::Status ContextInit(nikss_context_t* nikss_ctx,
                                     nikss_table_entry_t* entry,
                                     nikss_table_entry_ctx_t* entry_ctx,
                                     nikss_action_t* action_ctx,
                                     int node_id, std::string nikss_name) = 0;

  // Add matches from request to entry
  virtual ::util::Status AddMatchesToEntry(const ::p4::v1::TableEntry& request,
                                           const ::p4::config::v1::Table table,
                                           nikss_table_entry_t* entry) = 0;

  // Add actions from request to entry
  virtual ::util::Status AddActionsToEntry(const ::p4::v1::TableEntry& request,
                                           const ::p4::config::v1::Table table,
                                           const ::p4::config::v1::Action action,
                                           nikss_action_t* action_ctx,
                                           nikss_table_entry_ctx_t* entry_ctx,
                                           nikss_table_entry_t* entry) = 0;

  // Push table entry
  virtual ::util::Status PushTableEntry(const ::p4::v1::Update::Type type,
                                        const ::p4::config::v1::Table table,
                                        nikss_table_entry_ctx_t* entry_ctx,
                                        nikss_table_entry_t* entry) = 0;

  // Cleanup
  virtual ::util::Status Cleanup(nikss_context_t* nikss_ctx,
                                 nikss_table_entry_t* entry,
                                 nikss_table_entry_ctx_t* entry_ctx,
                                 nikss_action_t* action_ctx) = 0;

 protected:
  // Default constructor. To be called by the Mock class instance only.
  NikssInterface() {}
};

}  // namespace nikss
}  // namespace hal
}  // namespace stratum

#endif  // STRATUM_HAL_LIB_NIKSS_NIKSS_INTERFACE_H_
