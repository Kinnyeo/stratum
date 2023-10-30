#include "stratum/hal/lib/nikss/nikss_node.h"

#include <memory>

#include "absl/synchronization/mutex.h"
#include "absl/memory/memory.h"
#include "stratum/lib/macros.h"

extern "C" {
#include "nikss/nikss.h"
#include "nikss/nikss_pipeline.h"
}

namespace stratum {
namespace hal {
namespace nikss {

NikssNode::NikssNode(NikssInterface* nikss_interface, 
                     uint64 node_id)
    : config_(),
      nikss_interface_(ABSL_DIE_IF_NULL(nikss_interface)),
      p4_info_manager_(nullptr),
      node_id_(node_id) {}

NikssNode::NikssNode()
    : config_(),
      nikss_interface_(nullptr),
      p4_info_manager_(nullptr),
      node_id_(0) {}

NikssNode::~NikssNode() = default;

// Factory function for creating the instance of the class.
std::unique_ptr<NikssNode> NikssNode::CreateInstance(
    NikssInterface* nikss_interface, 
    uint64 node_id) {
  return absl::WrapUnique(
      new NikssNode(nikss_interface, node_id));
}

::util::Status NikssNode::PushForwardingPipelineConfig(
    const ::p4::v1::ForwardingPipelineConfig& config,
    std::map<uint64, std::map<uint32, NikssChassisManager::PortConfig>> chassis_config) {
  // SaveForwardingPipelineConfig + CommitForwardingPipelineConfig
  RETURN_IF_ERROR(SaveForwardingPipelineConfig(config));

  auto p4_info = config.p4info();
  std::unique_ptr<P4InfoManager> p4_info_manager =
      absl::make_unique<P4InfoManager>(p4_info);
  RETURN_IF_ERROR(p4_info_manager->InitializeAndVerify());
  p4_info_manager_ = std::move(p4_info_manager);

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

  bool success = true;
  for (const auto& update : req.updates()) {
    ::util::Status status = ::util::OkStatus();
    switch (update.entity().entity_case()) {
      case ::p4::v1::Entity::kTableEntry: {
        status = WriteTableEntry(
            update.type(), update.entity().table_entry());
        break;
      }
      default: {
        status = MAKE_ERROR(ERR_UNIMPLEMENTED)
                 << "Unsupported entity type: " << update.ShortDebugString();
        break;
      }
    }
    success &= status.ok();
    results->push_back(status);
  }

  if (!success) {
    return MAKE_ERROR(ERR_AT_LEAST_ONE_OPER_FAILED)
           << "One or more write operations failed.";
  }

  LOG(INFO) << "P4-based forwarding entities written successfully to node with "
            << "ID " << node_id_ << ".";
  return ::util::OkStatus();
}

::util::Status NikssNode::WriteTableEntry(
    const ::p4::v1::Update::Type type,
    const ::p4::v1::TableEntry& table_entry) {

    auto table_id = table_entry.table_id();
    auto action_id = table_entry.action().action().action_id();

    ASSIGN_OR_RETURN(auto table, p4_info_manager_->FindTableByID(
                                   table_id));

    ASSIGN_OR_RETURN(auto action, p4_info_manager_->FindActionByID(
                                   action_id));

    auto name = table.preamble().name();
    LOG(INFO) << "New request table with id: " 
              << table_id << " and name: " << name;
    
    // Nikss contexts declaration
    auto nikss_ctx = absl::make_unique<nikss_context_t>();
    auto entry = absl::make_unique<nikss_table_entry_t>();
    auto entry_ctx = absl::make_unique<nikss_table_entry_ctx_t>();
    auto action_ctx = absl::make_unique<nikss_action_t>();

    ::util::Status status;
    // Init nikss contexts
    status = nikss_interface_->ContextInit(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                               action_ctx.get(), node_id_, name);
    if (status != ::util::OkStatus()){
      RETURN_IF_ERROR(nikss_interface_->Cleanup(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get()));
    }

    // Add matches from request to entry
    status = nikss_interface_->AddMatchesToEntry(table_entry, table, entry.get());
    if (status != ::util::OkStatus()){
      RETURN_IF_ERROR(nikss_interface_->Cleanup(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get()));
    }

    // Add actions from request to entry
    status = nikss_interface_->AddActionsToEntry(table_entry, table, action,
                                      action_ctx.get(), entry_ctx.get(), entry.get());
    if (status != ::util::OkStatus()){
      RETURN_IF_ERROR(nikss_interface_->Cleanup(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get()));
    }

    // Push table entry
    status = nikss_interface_->PushTableEntry(type, table, entry_ctx.get(), entry.get());
    if (status != ::util::OkStatus()){
      RETURN_IF_ERROR(nikss_interface_->Cleanup(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get()));
    }

    // Cleanup
    RETURN_IF_ERROR(nikss_interface_->Cleanup(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get()));

  return ::util::OkStatus();
}

}  // namespace nikss
}  // namespace hal
}  // namespace stratum
