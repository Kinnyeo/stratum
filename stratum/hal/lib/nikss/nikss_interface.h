#ifndef STRATUM_HAL_LIB_NIKSS_NIKSS_INTERFACE_H_
#define STRATUM_HAL_LIB_NIKSS_NIKSS_INTERFACE_H_

#include "stratum/glue/status/status.h"
#include "stratum/glue/status/statusor.h"
#include "stratum/glue/integral_types.h"
#include "stratum/hal/lib/common/writer_interface.h"
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
  virtual ::util::Status AddPort(int pipeline_id,
      const std::string& port_name) = 0;

  virtual ::util::Status ContextInit(nikss_context_t* nikss_ctx,
      nikss_counter_context_t* counter_ctx,
      nikss_counter_entry_t* nikss_counter,
      int node_id, std::string nikss_name) = 0;
  virtual ::util::StatusOr<::p4::v1::CounterEntry> ReadCounterEntry(
      nikss_counter_entry_t* nikss_counter,
      nikss_counter_type_t counter_type) = 0;
  virtual ::util::Status ReadSingleCounterEntry(
      const ::p4::v1::CounterEntry& counter_entry,
      nikss_counter_entry_t* nikss_counter,
      nikss_counter_context_t* counter_ctx,
      WriterInterface<::p4::v1::ReadResponse>* writer) = 0;
  virtual ::util::Status ReadAllCounterEntries(
      const ::p4::v1::CounterEntry& counter_entry,
      nikss_counter_context_t* counter_ctx,
      WriterInterface<::p4::v1::ReadResponse>* writer) = 0;
  virtual ::util::Status Cleanup(nikss_context_t* nikss_ctx,
      nikss_counter_context_t* counter_ctx,
      nikss_counter_entry_t* nikss_counter) = 0;

 protected:
  // Default constructor. To be called by the Mock class instance only.
  NikssInterface() {}
};

}  // namespace nikss
}  // namespace hal
}  // namespace stratum

#endif  // STRATUM_HAL_LIB_NIKSS_NIKSS_INTERFACE_H_
