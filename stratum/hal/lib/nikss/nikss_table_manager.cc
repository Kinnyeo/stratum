#include "absl/strings/match.h"
#include "absl/synchronization/notification.h"

#include "stratum/hal/lib/nikss/nikss_table_manager.h"
#include "stratum/hal/lib/p4/utils.h"
#include "stratum/lib/utils.h"

//#include "stratum/glue/status/status.h"
//#include "stratum/lib/utils.h"
#include "stratum/lib/macros.h"

//#include "absl/memory/memory.h"
//#include "absl/synchronization/mutex.h"

namespace stratum {
namespace hal {
namespace nikss {

NikssTableManager::NikssTableManager(
    //OperationMode mode, 
    NikssInterface* nikss_interface,
    //BfrtP4RuntimeTranslator* bfrt_p4runtime_translator,
    int device)
    : //mode_(mode),
      nikss_interface_(ABSL_DIE_IF_NULL(nikss_interface)),
      //bfrt_p4runtime_translator_(ABSL_DIE_IF_NULL(bfrt_p4runtime_translator)),
      //p4_info_manager_(nullptr),
      device_(device) 
      {}

NikssTableManager::NikssTableManager()
    : //mode_(OPERATION_MODE_STANDALONE),
      nikss_interface_(nullptr),
      //bfrt_p4runtime_translator_(nullptr),
      //p4_info_manager_(nullptr),
      device_(-1) {}

NikssTableManager::~NikssTableManager() = default;

std::unique_ptr<NikssTableManager> NikssTableManager::CreateInstance(
    //OperationMode mode, 
    NikssInterface* nikss_interface,
    //BfrtP4RuntimeTranslator* bfrt_p4runtime_translator, 
    int device) {
  return absl::WrapUnique(new NikssTableManager(
      //mode, 
      nikss_interface, 
      //bfrt_p4runtime_translator, 
      device));
}

::util::Status NikssTableManager::BuildTableKey(
    const ::p4::v1::TableEntry& table_entry,
    NikssInterface::TableKeyInterface* table_key) {
  //RET_CHECK(table_key);
  bool needs_priority = false;
  /*ASSIGN_OR_RETURN(auto table,
                   p4_info_manager_->FindTableByID(table_entry.table_id()));*/

  //for (const auto& expected_match_field : table.match_fields()) {
    /*needs_priority = needs_priority ||
                     expected_match_field.match_type() ==
                         ::p4::config::v1::MatchField::TERNARY ||
                     expected_match_field.match_type() ==
                         ::p4::config::v1::MatchField::RANGE; 
    auto expected_field_id = expected_match_field.id();
    auto it =
        std::find_if(table_entry.match().begin(), table_entry.match().end(),
                     [expected_field_id](const ::p4::v1::FieldMatch& match) {
                       return match.field_id() == expected_field_id;
                     });
    if (it != table_entry.match().end()) {
      auto mk = *it;
      switch (mk.field_match_type_case()) {
        case ::p4::v1::FieldMatch::kExact: {
          RET_CHECK(expected_match_field.match_type() ==
                    ::p4::config::v1::MatchField::EXACT)
              << "Found match field of type EXACT does not fit match field "
              << expected_match_field.ShortDebugString() << ".";
          RET_CHECK(!IsDontCareMatch(mk.exact()))
              << "Don't care match " << mk.ShortDebugString()
              << " must be omitted.";
          RETURN_IF_ERROR(
              table_key->SetExact(mk.field_id(), mk.exact().value()));
          break;
        }
        case ::p4::v1::FieldMatch::kTernary: {
          RET_CHECK(expected_match_field.match_type() ==
                    ::p4::config::v1::MatchField::TERNARY)
              << "Found match field of type TERNARY does not fit match field "
              << expected_match_field.ShortDebugString() << ".";
          RET_CHECK(!IsDontCareMatch(mk.ternary()))
              << "Don't care match " << mk.ShortDebugString()
              << " must be omitted.";
          RETURN_IF_ERROR(table_key->SetTernary(
              mk.field_id(), mk.ternary().value(), mk.ternary().mask()));
          break;
        }
        case ::p4::v1::FieldMatch::kLpm: {
          RET_CHECK(expected_match_field.match_type() ==
                    ::p4::config::v1::MatchField::LPM)
              << "Found match field of type LPM does not fit match field "
              << expected_match_field.ShortDebugString() << ".";
          RET_CHECK(!IsDontCareMatch(mk.lpm()))
              << "Don't care match " << mk.ShortDebugString()
              << " must be omitted.";
          RETURN_IF_ERROR(table_key->SetLpm(mk.field_id(), mk.lpm().value(),
                                            mk.lpm().prefix_len()));
          break;
        }
        case ::p4::v1::FieldMatch::kRange: {
          RET_CHECK(expected_match_field.match_type() ==
                    ::p4::config::v1::MatchField::RANGE)
              << "Found match field of type Range does not fit match field "
              << expected_match_field.ShortDebugString() << ".";
          RET_CHECK(
              !IsDontCareMatch(mk.range(), expected_match_field.bitwidth()))
              << "Don't care match " << mk.ShortDebugString()
              << " must be omitted.";
          RETURN_IF_ERROR(table_key->SetRange(mk.field_id(), mk.range().low(),
                                              mk.range().high()));
          break;
        }
        case ::p4::v1::FieldMatch::kOptional:
          RET_CHECK(!IsDontCareMatch(mk.optional()))
              << "Don't care match field " << mk.ShortDebugString()
              << " must be omitted.";
          ABSL_FALLTHROUGH_INTENDED; 
        default:
          return MAKE_ERROR(ERR_INVALID_PARAM)
                 << "Invalid or unsupported match key: "
                 << mk.ShortDebugString();
      }
    } else {
      switch (expected_match_field.match_type()) {
        case ::p4::config::v1::MatchField::EXACT:
        case ::p4::config::v1::MatchField::TERNARY:
        case ::p4::config::v1::MatchField::LPM:
          // Nothing to be done. Zero values implement a don't care match.
          break;
        case ::p4::config::v1::MatchField::RANGE: {
          RETURN_IF_ERROR(table_key->SetRange(
              expected_field_id,
              RangeDefaultLow(expected_match_field.bitwidth()),
              RangeDefaultHigh(expected_match_field.bitwidth())));
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
  }

  // Priority handling.
  if (!needs_priority && table_entry.priority()) {
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "Non-zero priority for exact/LPM match.";
  } else if (needs_priority && table_entry.priority() == 0) {
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "Zero priority for ternary/range/optional match.";
  } else if (needs_priority) {
    ASSIGN_OR_RETURN(uint64 priority,
                     ConvertPriorityFromP4rtToBfrt(table_entry.priority()));
    RETURN_IF_ERROR(table_key->SetPriority(priority));
  }*/

  return ::util::OkStatus();
}

//TODO
::util::Status NikssTableManager::WriteTableEntry(
    //std::shared_ptr<NikssInterface::SessionInterface> session,
    const ::p4::v1::Update::Type type,
    const ::p4::v1::TableEntry& table_entry) {
  /*RET_CHECK(type != ::p4::v1::Update::UNSPECIFIED)
      << "Invalid update type " << type;*/
    LOG(INFO) << "TableManager_WriteTableEntry ";
    LOG(INFO) << "table_id = " << table_entry.table_id() << ".";
      
      
  //absl::ReaderMutexLock l(&lock_);
  /*
  ASSIGN_OR_RETURN(const auto& translated_table_entry,
                   bfrt_p4runtime_translator_->TranslateTableEntry(
                       table_entry,true));

  ASSIGN_OR_RETURN(auto table, p4_info_manager_->FindTableByID(
                                   translated_table_entry.table_id()));
  ASSIGN_OR_RETURN(uint32 table_id, bf_sde_interface_->GetBfRtId(
                                        translated_table_entry.table_id()));

  if (!translated_table_entry.is_default_action()) {
    if (table.is_const_table()) {
      return MAKE_ERROR(ERR_PERMISSION_DENIED)
             << "Can't write to table " << table.preamble().name()
             << " because it has const entries.";
    }
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

}
}
}