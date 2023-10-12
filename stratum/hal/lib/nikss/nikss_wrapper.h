#ifndef STRATUM_HAL_LIB_NIKSS_NIKSS_WRAPPER_H_
#define STRATUM_HAL_LIB_NIKSS_NIKSS_WRAPPER_H_

#include <string>

#include "absl/synchronization/mutex.h"
#include "stratum/glue/status/status.h"
#include "stratum/hal/lib/nikss/nikss_interface.h"
//#include "nikss/nikss_session.hpp"

namespace stratum {
namespace hal {
namespace nikss {

// The "NikssWrapper" is an implementation of NikssInterface which is used
// to talk to the Linux eBPF subsystem via the NIKSS APIs calls.
class NikssWrapper : public NikssInterface {
 public:

    // Wrapper around the nikss session object.
    /*
  class Session : public NikssInterface::SessionInterface {
   public:
    // SessionInterface public methods.
    ::util::Status BeginBatch() override {
      RETURN_IF_BFRT_ERROR(nikss_session_->beginBatch());
      return ::util::OkStatus();
    }
    ::util::Status EndBatch() override {
      RETURN_IF_BFRT_ERROR(nikss_session_->endBatch( true));
      RETURN_IF_BFRT_ERROR(nikss_session_->sessionCompleteOperations());
      return ::util::OkStatus();
    }

    static ::util::StatusOr<std::shared_ptr<NikssInterface::SessionInterface>>
    CreateSession() {
      auto nikss_session = nikss::NikssSession::sessionCreate();
      RET_CHECK(nikss_session) << "Failed to create new session.";
      VLOG(1) << "Started new Nikss session with ID "
              << nikss_session->sessHandleGet();

      return std::shared_ptr<NikssInterface::SessionInterface>(
          new Session(nikss_session));
    }

    // Stores the underlying SDE session.
    std::shared_ptr<nikss::NikssSession> nikss_session_;

   private:
    // Private constructor. Use CreateSession() instead.
    Session() {}
    explicit Session(std::shared_ptr<nikss::NikssSession> nikss_session)
        : nikss_session_(nikss_session) {}*/
  //};
  
  // NikssInterface public methods.
  ::util::Status AddPort(int pipeline_id,
                         const std::string& port_name);
  ::util::Status DelPort(int pipeline_id,
                         const std::string& port_name);
  ::util::Status AddPipeline(int pipeline_id,
                         const std::string filepath) override;

  // add table entry - z nikss node

  static NikssWrapper* CreateSingleton() LOCKS_EXCLUDED(init_lock_);

  // NikssWrapper is neither copyable nor movable.
  NikssWrapper(const NikssWrapper&) = delete;
  NikssWrapper& operator=(const NikssWrapper&) = delete;
  NikssWrapper(NikssWrapper&&) = delete;
  NikssWrapper& operator=(NikssWrapper&&) = delete;

 protected:
  // RW mutex lock for protecting the singleton instance initialization and
  // reading it back from other threads. Unlike other singleton classes, we
  // use RW lock as we need the pointer to class to be returned.
  static absl::Mutex init_lock_;

  // The singleton instance.
  static NikssWrapper* singleton_ GUARDED_BY(init_lock_);

 private:

  // Private constructor, use CreateSingleton and GetSingleton().
  NikssWrapper();
};

}  // namespace nikss
}  // namespace hal
}  // namespace stratum


#endif  // STRATUM_HAL_LIB_NIKSS_NIKSS_WRAPPER_H_
