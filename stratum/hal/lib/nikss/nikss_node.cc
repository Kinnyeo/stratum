#include "stratum/hal/lib/nikss/nikss_node.h"

#include <memory>

#include "absl/synchronization/mutex.h"
#include "absl/memory/memory.h"
#include "stratum/lib/macros.h"

namespace stratum {
namespace hal {
namespace nikss {

NikssNode::NikssNode(NikssInterface* nikss_interface, 
                     NikssTableManager* nikss_table_manager,
                     uint64 node_id)
    : config_(),
      nikss_interface_(ABSL_DIE_IF_NULL(nikss_interface)),
      nikss_table_manager_(ABSL_DIE_IF_NULL(nikss_table_manager)),
      node_id_(node_id) {}

NikssNode::NikssNode()
    : config_(),
      nikss_interface_(nullptr),
      nikss_table_manager_(nullptr),
      node_id_(0) {}

NikssNode::~NikssNode() = default;

// Factory function for creating the instance of the class.
std::unique_ptr<NikssNode> NikssNode::CreateInstance(
    NikssInterface* nikss_interface, 
    NikssTableManager* nikss_table_manager,
    uint64 node_id) {
  return absl::WrapUnique(
      new NikssNode(nikss_interface, nikss_table_manager, node_id));
}

::util::Status NikssNode::PushForwardingPipelineConfig(
    const ::p4::v1::ForwardingPipelineConfig& config,
    std::map<uint64, std::map<uint32, NikssChassisManager::PortConfig>> chassis_config) {
  // SaveForwardingPipelineConfig + CommitForwardingPipelineConfig
  RETURN_IF_ERROR(SaveForwardingPipelineConfig(config));
  return CommitForwardingPipelineConfig(chassis_config);
}

::util::Status NikssNode::SaveForwardingPipelineConfig(
    const ::p4::v1::ForwardingPipelineConfig& config) {
  config_ = config;
  return ::util::OkStatus();
}

::util::Status NikssNode::CommitForwardingPipelineConfig(std::map<uint64, std::map<uint32, 
  NikssChassisManager::PortConfig>> chassis_config) {
    
  RETURN_IF_ERROR(nikss_interface_->AddPipeline(node_id_, config_.p4_device_config()));
  
  for (auto it = chassis_config[node_id_].begin(); it != chassis_config[node_id_].end(); it++) {
    uint32 key = it->first;
    NikssChassisManager::PortConfig config = it->second;
    LOG(INFO) << "Adding new port with name " << config.name << ".";
    RETURN_IF_ERROR(nikss_interface_->AddPort(node_id_, config.name));
  }
  
  return ::util::OkStatus();
}

::util::Status NikssNode::VerifyForwardingPipelineConfig(
    const ::p4::v1::ForwardingPipelineConfig& config) const {
  RET_CHECK(config.has_p4info()) << "Missing P4 info";
  RET_CHECK(!config.p4_device_config().empty()) << "Missing P4 device config";
  return ::util::OkStatus();
}

::util::Status NikssNode::WriteForwardingEntries(
    const ::p4::v1::WriteRequest& req, std::vector<::util::Status>* results) {
  absl::WriterMutexLock l(&lock_);
  RET_CHECK(req.device_id() == node_id_)
      << "Request device id must be same as id of this NikssNode.";
  RET_CHECK(req.atomicity() == ::p4::v1::WriteRequest::CONTINUE_ON_ERROR)
      << "Request atomicity "
      << ::p4::v1::WriteRequest::Atomicity_Name(req.atomicity())
      << " is not supported.";
      
  //tymczasowo bez tego    
  /*
  if (!initialized_ || !pipeline_initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }*/

  LOG(INFO) << "WriteForwardingEntries";

  bool success = true;
  //ASSIGN_OR_RETURN(auto session, nikss_interface_->CreateSession());
  //RETURN_IF_ERROR(session->BeginBatch());
  for (const auto& update : req.updates()) {
    ::util::Status status = ::util::OkStatus();
    switch (update.entity().entity_case()) {
      case ::p4::v1::Entity::kTableEntry:
        status = nikss_table_manager_->WriteTableEntry(
            //session, 
            update.type(), update.entity().table_entry());
        break;
      /*case ::p4::v1::Entity::kExternEntry:
        status = WriteExternEntry(session, update.type(),
                                  update.entity().extern_entry());
        break;
      case ::p4::v1::Entity::kActionProfileMember:
        status = nikss_table_manager_->WriteActionProfileMember(
            session, update.type(), update.entity().action_profile_member());
        break;
      case ::p4::v1::Entity::kActionProfileGroup:
        status = nikss_table_manager_->WriteActionProfileGroup(
            session, update.type(), update.entity().action_profile_group());
        break;
      case ::p4::v1::Entity::kPacketReplicationEngineEntry:
        status = nikss_table_manager_->WritePreEntry(
            session, update.type(),
            update.entity().packet_replication_engine_entry());
        break;
      case ::p4::v1::Entity::kDirectCounterEntry:
        status = nikss_table_manager_->WriteDirectCounterEntry(
            session, update.type(), update.entity().direct_counter_entry());
        break;
      case ::p4::v1::Entity::kCounterEntry:
        status = bfrt_counter_manager_->WriteIndirectCounterEntry(
            session, update.type(), update.entity().counter_entry());
        break;
      case ::p4::v1::Entity::kRegisterEntry: {
        status = nikss_table_manager_->WriteRegisterEntry(
            session, update.type(), update.entity().register_entry());
        break;
      }
      case ::p4::v1::Entity::kMeterEntry: {
        status = nikss_table_manager_->WriteMeterEntry(
            session, update.type(), update.entity().meter_entry());
        break;
      }
      case ::p4::v1::Entity::kDirectMeterEntry:
      case ::p4::v1::Entity::kValueSetEntry:
      case ::p4::v1::Entity::kDigestEntry:   */
      default:
        status = MAKE_ERROR(ERR_UNIMPLEMENTED)
                 << "Unsupported entity type: " << update.ShortDebugString();
        break;
    }
    success &= status.ok();
    results->push_back(status);
  }
  //RETURN_IF_ERROR(session->EndBatch());

  if (!success) {
    return MAKE_ERROR(ERR_AT_LEAST_ONE_OPER_FAILED)
           << "One or more write operations failed.";
  }

  LOG(INFO) << "P4-based forwarding entities written successfully to node with "
            << "ID " << node_id_ << ".";
  return ::util::OkStatus();
}

}  // namespace nikss
}  // namespace hal
}  // namespace stratum