#include "anonymizer.h"




int mask_ngap_message(ogs_ngap_message_t *message)
{
    NGAP_NGAP_PDU_t *pdu = message;
    NGAP_InitiatingMessage_t *initiatingMessage = NULL;
    NGAP_SuccessfulOutcome_t *successfulOutcome = NULL;
    NGAP_UnsuccessfulOutcome_t *unsuccessfulOutcome = NULL;

    switch (pdu->present) {
        case NGAP_NGAP_PDU_PR_initiatingMessage:
            initiatingMessage = pdu->choice.initiatingMessage;
            // ogs_assert(initiatingMessage);

            switch (initiatingMessage->procedureCode) {
            case NGAP_ProcedureCode_id_NGSetup:
                // ogs_error("NGAP_ProcedureCode_id_NGSetup");
                // ngap_handle_ng_setup_request(gnb, pdu);
                break;
            // case NGAP_ProcedureCode_id_InitialUEMessage:
            //     ngap_handle_initial_ue_message(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UplinkNASTransport:
            //     ngap_handle_uplink_nas_transport(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UERadioCapabilityInfoIndication:
            //     ngap_handle_ue_radio_capability_info_indication(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UEContextReleaseRequest:
            //     ngap_handle_ue_context_release_request( gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_PathSwitchRequest:
            //     ngap_handle_path_switch_request(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UplinkRANConfigurationTransfer:
            //     pkbuf = e->pkbuf;
            //     ogs_assert(pkbuf);

            //     ngap_handle_uplink_ran_configuration_transfer(gnb, pdu, pkbuf);
            //     break;
            // case NGAP_ProcedureCode_id_HandoverPreparation:
            //     ngap_handle_handover_required(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UplinkRANStatusTransfer:
            //     ngap_handle_uplink_ran_status_transfer(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_HandoverNotification:
            //     ngap_handle_handover_notification(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_HandoverCancel:
            //     ngap_handle_handover_cancel(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_RANConfigurationUpdate:
            //     ngap_handle_ran_configuration_update(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_NGReset:
            //     ngap_handle_ng_reset(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_ErrorIndication:
            //     ngap_handle_error_indication(gnb, pdu);
            //     break;
            // default:
            //     ogs_error("Not implemented(choice:%d, proc:%d)",
            //             pdu->present, (int)initiatingMessage->procedureCode);
            //     break;
            }
            break;
        case NGAP_NGAP_PDU_PR_successfulOutcome :
            // successfulOutcome = pdu->choice.successfulOutcome;
            // ogs_assert(successfulOutcome);

            // switch (successfulOutcome->procedureCode) {
            // case NGAP_ProcedureCode_id_InitialContextSetup:
            //     ngap_handle_initial_context_setup_response(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_PDUSessionResourceSetup:
            //     ngap_handle_pdu_session_resource_setup_response(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_PDUSessionResourceModify:
            //     ngap_handle_pdu_session_resource_modify_response(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_PDUSessionResourceRelease:
            //     ngap_handle_pdu_session_resource_release_response(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UEContextModification:
            //     ngap_handle_ue_context_modification_response(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UEContextRelease:
            //     ngap_handle_ue_context_release_complete(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_HandoverResourceAllocation:
            //     ngap_handle_handover_request_ack(gnb, pdu);
            //     break;
            // default:
            //     ogs_error("Not implemented(choice:%d, proc:%d)",
            //             pdu->present, (int)successfulOutcome->procedureCode);
            //     break;
            // }
            // break;
        case NGAP_NGAP_PDU_PR_unsuccessfulOutcome :
            // unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
            // ogs_assert(unsuccessfulOutcome);

            // switch (unsuccessfulOutcome->procedureCode) {
            // case NGAP_ProcedureCode_id_InitialContextSetup :
            //     ngap_handle_initial_context_setup_failure(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_UEContextModification:
            //     ngap_handle_ue_context_modification_failure(gnb, pdu);
            //     break;
            // case NGAP_ProcedureCode_id_HandoverResourceAllocation :
            //     ngap_handle_handover_failure(gnb, pdu);
            //     break;
            // default:
            //     ogs_error("Not implemented(choice:%d, proc:%d)",
            //             pdu->present, (int)unsuccessfulOutcome->procedureCode);
            //     break;
            // }
            break;
        default:
            // ogs_error("Not implemented(choice:%d)", pdu->present);
            break;
    }
    return 0;
}

