#ifndef STRATUM_HAL_LIB_NIKSS_NIKSS_TABLE_MANAGER_H_
#define STRATUM_HAL_LIB_NIKSS_NIKSS_TABLE_MANAGER_H_

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "stratum/glue/status/status.h"
//#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "stratum/hal/lib/nikss/nikss_interface.h"

namespace stratum {
namespace hal {
namespace nikss {

class NikssTableManager {
 public:
  virtual ~NikssTableManager();

  // Writes a table entry.
  virtual ::util::Status WriteTableEntry(
      //std::shared_ptr<NikssInterface::SessionInterface> session,
      const ::p4::v1::Update::Type type,
      const ::p4::v1::TableEntry& table_entry) LOCKS_EXCLUDED(lock_);
    
  // Creates a table manager instance.
  static std::unique_ptr<NikssTableManager> CreateInstance(
      //OperationMode mode, 
      NikssInterface* nikss_interface,
      //BfrtP4RuntimeTranslator* bfrt_p4runtime_translator, 
      int device);

 private:

    NikssInterface* nikss_interface_;

    // Private constructor. Use CreateInstance() to create an instance of this
    // class.
    NikssTableManager(NikssInterface* nikss_interface, int device);

    ::util::Status BuildTableKey(const ::p4::v1::TableEntry& table_entry,
                               NikssInterface::TableKeyInterface* table_key)
      SHARED_LOCKS_REQUIRED(lock_);

    const int device_;

 protected:
    // Default constructor. To be called by the Mock class instance only.
    NikssTableManager();

};

}
}
}

#endif //STRATUM_HAL_LIB_NIKSS_NIKSS_TABLE_MANAGER_H_