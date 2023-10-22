#include "stratum/hal/lib/nikss/nikss_node.h"

#include <memory>

#include "absl/synchronization/mutex.h"
#include "absl/memory/memory.h"
#include "stratum/lib/macros.h"
#include <vector>

namespace stratum {
namespace hal {
namespace nikss {

NikssNode::NikssNode(NikssInterface* nikss_interface, 
                     uint64 node_id)
    : config_(),
      nikss_interface_(ABSL_DIE_IF_NULL(nikss_interface)),
      //nikss_table_manager_(ABSL_DIE_IF_NULL(nikss_table_manager)),
      p4_info_manager_(nullptr),
      node_id_(node_id) {}

NikssNode::NikssNode()
    : config_(),
      nikss_interface_(nullptr),
      //nikss_table_manager_(nullptr),
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
  //ASSIGN_OR_RETURN(auto session, nikss_interface_->CreateSession());
  //RETURN_IF_ERROR(session->BeginBatch());
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
  //RETURN_IF_ERROR(session->EndBatch());

  if (!success) {
    return MAKE_ERROR(ERR_AT_LEAST_ONE_OPER_FAILED)
           << "One or more write operations failed.";
  }

  LOG(INFO) << "P4-based forwarding entities written successfully to node with "
            << "ID " << node_id_ << ".";
  return ::util::OkStatus();
}

::util::Status NikssNode::WriteTableEntry(
    //std::shared_ptr<NikssInterface::SessionInterface> session,
    const ::p4::v1::Update::Type type,
    const ::p4::v1::TableEntry& table_entry) {
  /*RET_CHECK(type != ::p4::v1::Update::UNSPECIFIED)
      << "Invalid update type " << type;*/
    auto table_id = table_entry.table_id();
    auto action_id = table_entry.action().action().action_id();
    //LOG(INFO) << "WriteTableEntry";

    ASSIGN_OR_RETURN(auto table, p4_info_manager_->FindTableByID(
                                   table_id));

    ASSIGN_OR_RETURN(auto action, p4_info_manager_->FindActionByID(
                                   action_id));

    //LOG(INFO) << "Action: " << action.preamble().name();
    auto name = table.preamble().name();
    LOG(INFO) << "New request table with id: " 
              << table_id << " and name: " << name;

    /*
    for (const auto& match : table.action_refs()) {
      for (const auto& an : match.annotations())
      LOG(INFO) << "action: " << an;
    }*/

    // Search for all match fields ids in p4info file
    /*std::vector<int> p4info_match_ids;
    for (const auto& match : table.match_fields()) {
      //LOG(INFO) << "match: " << match.id();
      p4info_match_ids.push_back(match.id());
    }

    for (::p4::v1::FieldMatch matches : table_entry.match()){
      for (auto expected_id : p4info_match_ids){
        if (matches.field_id() == expected_id){
          std::string* match_exact_value = matches.mutable_exact()->mutable_value()
          LOG(INFO) << "match name: " << 
          LOG(INFO) << "match value: " << *match_exact_value;
          break;
        }
      }

      //std::string* val = matches.mutable_exact()->mutable_value();
        //LOG(INFO) << "match: " << *val;
    }*/


    // Search for all match fields ids in request
    std::vector<int> request_match_ids;
    for (::p4::v1::FieldMatch match : table_entry.match()) {
      request_match_ids.push_back(match.field_id());
    }

    for (const auto& expected_match : table.match_fields()){
      for (auto match_id : request_match_ids){
        if (expected_match.id() == match_id){
          LOG(INFO) << "Found match with id: " << expected_match.id() 
                    << " and name: " << expected_match.name();
          break;
        }
      }
    }

    // Finding actions from request in p4info file
    for (const auto& p4info_action : table.action_refs()){
      if (action_id == p4info_action.id()){
        LOG(INFO) << "Found action with id: " << action_id
                  << " and name: " << action.preamble().name();
        break;
      }
    }

    //LOG(INFO) << "action: " << table_entry.action().action().action_id(); 
    // api nikss - przejrzec

    // parse_key_data(argc, argv, entry);
    //
  /*
  if (!translated_table_entry.is_default_action()) {
    if (table.is_const_table()) {
      return MAKE_ERROR(ERR_PERMISSION_DENIED)
             << "Can't write to table " << table.preamble().name()
             << " because it has const entries.";
    }*/
    /*
    ASSIGN_OR_RETURN(auto table_key,
                     bf_sde_interface_->CreateTableKey(table_id));
    RETURN_IF_ERROR(BuildTableKey(translated_table_entry, table_key.get()));

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

/*
::util::StatusOr<std::unique_ptr<BfSdeInterface::TableKeyInterface>>
TableKey::CreateTableKey(const bfrt::BfRtInfo* bfrt_info_, int table_id) {
  const bfrt::BfRtTable* table;
  RETURN_IF_BFRT_ERROR(bfrt_info_->bfrtTableFromIdGet(table_id, &table));
  std::unique_ptr<bfrt::BfRtTableKey> table_key;
  RETURN_IF_BFRT_ERROR(table->keyAllocate(&table_key));
  auto key = std::unique_ptr<BfSdeInterface::TableKeyInterface>(
      new TableKey(std::move(table_key)));
  return key;
}*/
/*
::util::StatusOr<::p4::v1::TableEntry> BfrtTableManager::BuildP4TableEntry(
    const ::p4::v1::TableEntry& request, //table entry
    const BfSdeInterface::TableKeyInterface* table_key,
    const BfSdeInterface::TableDataInterface* table_data) {
  ::p4::v1::TableEntry result;

  ASSIGN_OR_RETURN(auto table,
                   p4_info_manager_->FindTableByID(request.table_id()));
  result.set_table_id(request.table_id());

  bool has_priority_field = false;
  // Match keys
  for (const auto& expected_match_field : table.match_fields()) {
    ::p4::v1::FieldMatch match;  // Added to the entry later.
    match.set_field_id(expected_match_field.id());
    switch (expected_match_field.match_type()) {
      case ::p4::config::v1::MatchField::EXACT: {
        RETURN_IF_ERROR(table_key->GetExact( //useless
            expected_match_field.id(), match.mutable_exact()->mutable_value()));
        /*if (!IsDontCareMatch(match.exact())) {
          *result.add_match() = match;
        }*//*
        break;
      }
      case ::p4::config::v1::MatchField::TERNARY: {
        has_priority_field = true;
        std::string value, mask;
        RETURN_IF_ERROR(
            table_key->GetTernary(expected_match_field.id(), &value, &mask));
        match.mutable_ternary()->set_value(value);
        match.mutable_ternary()->set_mask(mask);
        if (!IsDontCareMatch(match.ternary())) {
          *result.add_match() = match;
        }
        break;
      }
      case ::p4::config::v1::MatchField::LPM: {
        std::string prefix;
        uint16 prefix_length;
        RETURN_IF_ERROR(table_key->GetLpm(expected_match_field.id(), &prefix,
                                          &prefix_length));
        match.mutable_lpm()->set_value(prefix);
        match.mutable_lpm()->set_prefix_len(prefix_length);
        if (!IsDontCareMatch(match.lpm())) {
          *result.add_match() = match;
        }
        break;
      }
      case ::p4::config::v1::MatchField::RANGE: { // not supported log
        LOG(INFO) << "Error: RANGE type is not supported";
        /*has_priority_field = true;
        std::string low, high;
        RETURN_IF_ERROR(
            table_key->GetRange(expected_match_field.id(), &low, &high));
        match.mutable_range()->set_low(low);
        match.mutable_range()->set_high(high);
        if (!IsDontCareMatch(match.range(), expected_match_field.bitwidth())) {
          *result.add_match() = match;*//*
        }
        break;
      }
      default:
        return MAKE_ERROR(ERR_INVALID_PARAM)
               << "Invalid field match type "
               << ::p4::config::v1::MatchField_MatchType_Name(
                      expected_match_field.match_type())
               << ".";
    }
  }

  // Default actions do not have a priority, even when the table usually
  // requires one. The SDE would return 0 (highest) which we must not translate.
  if (request.is_default_action()) {
    has_priority_field = false;
  }

  // Priority.
  if (has_priority_field) {
    uint32 bf_priority;
    RETURN_IF_ERROR(table_key->GetPriority(&bf_priority));
    ASSIGN_OR_RETURN(uint64 p4rt_priority,
                     ConvertPriorityFromBfrtToP4rt(bf_priority));
    result.set_priority(p4rt_priority);
  }

  // Action and action data
  int action_id;
  RETURN_IF_ERROR(table_data->GetActionId(&action_id));
  // TODO(max): perform check if action id is valid for this table.
  if (action_id) {
    ASSIGN_OR_RETURN(auto action, p4_info_manager_->FindActionByID(action_id));
    result.mutable_action()->mutable_action()->set_action_id(action_id);
    for (const auto& expected_param : action.params()) {
      std::string value;
      RETURN_IF_ERROR(table_data->GetParam(expected_param.id(), &value));
      auto* param = result.mutable_action()->mutable_action()->add_params();
      param->set_param_id(expected_param.id());
      param->set_value(value);
    }
  }

  // Action profile member id
  uint64 action_member_id;
  if (table_data->GetActionMemberId(&action_member_id).ok()) {
    result.mutable_action()->set_action_profile_member_id(action_member_id);
  }

  // Action profile group id
  uint64 selector_group_id;
  if (table_data->GetSelectorGroupId(&selector_group_id).ok()) {
    result.mutable_action()->set_action_profile_group_id(selector_group_id);
  }

  // Counter data, if applicable.
  uint64 bytes, packets;
  if (request.has_counter_data() &&
      table_data->GetCounterData(&bytes, &packets).ok()) {
    result.mutable_counter_data()->set_byte_count(bytes);
    result.mutable_counter_data()->set_packet_count(packets);
  }

  return result;
}

*/

}  // namespace nikss
}  // namespace hal
}  // namespace stratum
