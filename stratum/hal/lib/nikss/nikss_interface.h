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
  
  // TableKeyInterface is a proxy class for NIKSS table keys.
  class TableKeyInterface {
   public:
    virtual ~TableKeyInterface() {}

    // Sets an exact match key field.
    virtual ::util::Status SetExact(int id, const std::string& value) = 0;

    // Gets an exact match key field.
    virtual ::util::Status GetExact(int id, std::string* value) const = 0;

    // Sets a ternary match key field.
    virtual ::util::Status SetTernary(int id, const std::string& value,
                                      const std::string& mask) = 0;

    // Gets a ternary match key field.
    virtual ::util::Status GetTernary(int id, std::string* value,
                                      std::string* mask) const = 0;

    // Sets a LPM match key field.
    virtual ::util::Status SetLpm(int id, const std::string& prefix,
                                  uint16 prefix_length) = 0;

    // Gets a LPM match key field.
    virtual ::util::Status GetLpm(int id, std::string* prefix,
                                  uint16* prefix_length) const = 0;

    // Sets a range match key field.
    virtual ::util::Status SetRange(int id, const std::string& low,
                                    const std::string& high) = 0;

    // Gets a LPM match key field.
    virtual ::util::Status GetRange(int id, std::string* low,
                                    std::string* high) const = 0;

    // Sets the priority of this table key. 0 is the highest priority.
    virtual ::util::Status SetPriority(uint32 priority) = 0;

    // Gets the priority of this table key. 0 is the highest priority.
    virtual ::util::Status GetPriority(uint32* priority) const = 0;

    // Gets the BfRt (not P4) table ID associated with this table key.
    virtual ::util::Status GetTableId(uint32* table_id) const = 0;
  };

  // TableKeyInterface is a proxy class for NIKSS table data.
  class TableDataInterface {
   public:
    virtual ~TableDataInterface() {}

    // Sets a table data action parameter.
    virtual ::util::Status SetParam(int id, const std::string& value) = 0;

    // Get a table data action parameter.
    virtual ::util::Status GetParam(int id, std::string* value) const = 0;

    // Sets the $ACTION_MEMBER_ID field.
    virtual ::util::Status SetActionMemberId(uint64 action_member_id) = 0;

    // Gets the $ACTION_MEMBER_ID field.
    virtual ::util::Status GetActionMemberId(
        uint64* action_member_id) const = 0;

    // Sets the $SELECTOR_GROUP_ID field.
    virtual ::util::Status SetSelectorGroupId(uint64 selector_group_id) = 0;

    // Gets the $SELECTOR_GROUP_ID field.
    virtual ::util::Status GetSelectorGroupId(
        uint64* selector_group_id) const = 0;

    // Convenience function to update the counter values in the table data.
    // This hides the IDs for the $COUNTER_SPEC_BYTES fields.
    virtual ::util::Status SetCounterData(uint64 bytes, uint64 packets) = 0;

    // Get the counter values.
    virtual ::util::Status GetCounterData(uint64* bytes,
                                          uint64* packets) const = 0;

    // Get the action ID.
    virtual ::util::Status GetActionId(int* action_id) const = 0;

    // Resets all data fields.
    virtual ::util::Status Reset(int action_id) = 0;
  };

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
  virtual ::util::Status PushTableEntry(const ::p4::config::v1::Table table,
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
