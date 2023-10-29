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

  //absl::WriterMutexLock l(&lock_);
  //RET_CHECK(config.programs_size() == 1) << "Only one P4 program is supported.";
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
  /*P4PipelineConfig nikss_config;
  LOG(INFO) << config.p4_name();

  auto program = nikss_config.add_programs();
  program->set_name(config.p4_name());
  program->set_bfrt(config.bfruntime_info());*/
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
      
  /*
  if (!initialized_ || !pipeline_initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }*/

  LOG(INFO) << "WriteForwardingEntries";

  bool success = true;
  for (const auto& update : req.updates()) {
    ::util::Status status = ::util::OkStatus();
    switch (update.entity().entity_case()) {
      case ::p4::v1::Entity::kTableEntry:
        status = WriteTableEntry(
            update.type(), update.entity().table_entry());
        break;
      /*
      case ::p4::v1::Entity::kExternEntry:
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

    // Init nikss contexts
    RETURN_IF_ERROR(nikss_interface_->ContextInit(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get(), node_id_, name));

    // Add matches from request to entry
    RETURN_IF_ERROR(nikss_interface_->AddMatchesToEntry(table_entry, table, entry.get()));

    // Add actions from request to entry
    RETURN_IF_ERROR(nikss_interface_->AddActionsToEntry(table_entry, table, action,
                                      action_ctx.get(), entry_ctx.get(), entry.get()));

    // Push table entry
    RETURN_IF_ERROR(nikss_interface_->PushTableEntry(table, entry_ctx.get(), entry.get()));

    // Cleanup
    RETURN_IF_ERROR(nikss_interface_->Cleanup(nikss_ctx.get(), entry.get(), entry_ctx.get(), 
                                      action_ctx.get()));

/*
    ASSIGN_OR_RETURN(
        auto table_data,
        bf_sde_interface_->CreateTableData(
            table_id, translated_table_entry.action().action().action_id()));
    if (type == ::p4::v1::Update::INSERT || type == ::p4::v1::Update::MODIFY) {
      RETURN_IF_ERROR(BuildTableData(translated_table_entry, table_data.get()));
    }

    switch (type) {
      case ::p4::v1::Update::INSERT:
        RETURN_IF_ERROR(bf_sde_interface_->InsertTableEntry(
            device_, session, table_id, table_key.get(), table_data.get()));
        break;
      case ::p4::v1::Update::MODIFY:
        RETURN_IF_ERROR(bf_sde_interface_->ModifyTableEntry(
            device_, session, table_id, table_key.get(), table_data.get()));
        break;
      case ::p4::v1::Update::DELETE:
        RETURN_IF_ERROR(bf_sde_interface_->DeleteTableEntry(
            device_, session, table_id, table_key.get()));
        break;
      default:
        return MAKE_ERROR(ERR_INTERNAL)
               << "Unsupported update type: " << type << " in table entry "
               << translated_table_entry.ShortDebugString() << ".";
    }
  } else {
    RET_CHECK(type == ::p4::v1::Update::MODIFY)
        << "The table default entry can only be modified.";
    RET_CHECK(translated_table_entry.match_size() == 0)
        << "Default action must not contain match fields.";
    RET_CHECK(translated_table_entry.priority() == 0)
        << "Default action must not contain a priority field.";

    if (translated_table_entry.has_action()) {
      ASSIGN_OR_RETURN(
          auto table_data,
          bf_sde_interface_->CreateTableData(
              table_id, translated_table_entry.action().action().action_id()));
      RETURN_IF_ERROR(BuildTableData(translated_table_entry, table_data.get()));
      RETURN_IF_ERROR(bf_sde_interface_->SetDefaultTableEntry(
          device_, session, table_id, table_data.get()));
    } else {
      RETURN_IF_ERROR(bf_sde_interface_->ResetDefaultTableEntry(
          device_, session, table_id));
    }
  }*/

  return ::util::OkStatus();
}

}  // namespace nikss
}  // namespace hal
}  // namespace stratum
