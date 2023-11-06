/*
 * smf_sess.h
 *
 * 
 */

#ifndef _OpenAPI_smf_sess_H_
#define _OpenAPI_smf_sess_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "../../../crypt/ogs-crypt.h"

// #include "../../ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_pfcp_subnet_s2 {
    ogs_lnode_t     lnode;

    ogs_ipsubnet_t  sub;                    /* Subnet : 2001:db8:cafe::0/48 */
    ogs_ipsubnet_t  gw;                     /* Gateway : 2001:db8:cafe::1 */
    char            dnn[OGS_MAX_DNN_LEN+1]; /* DNN : "internet", "volte", .. */

#define OGS_MAX_NUM_OF_SUBNET_RANGE 16
    struct {
        const char *low;
        const char *high;
    } range[OGS_MAX_NUM_OF_SUBNET_RANGE];
    int num_of_range;

    int             family;         /* AF_INET or AF_INET6 */
    uint8_t         prefixlen;      /* prefixlen */
    // OGS_POOL(pool, ogs_pfcp_ue_ip_t);

    // ogs_pfcp_dev_t  *dev;           /* Related Context */
} ogs_pfcp_subnet_t2;

typedef struct ogs_pfcp_ue_ip_s2 {
    uint32_t        addr[4];
    bool            static_ip;

    /* Related Context */
    ogs_pfcp_subnet_t2    *subnet;
} ogs_pfcp_ue_ip_t2;

typedef struct OpenAPI_smf_sess_s OpenAPI_smf_sess_t;
typedef struct OpenAPI_smf_sess_s {
//     ogs_sbi_object_t sbi;

//     uint32_t        index;              /* An index of this node */
//     ogs_pool_id_t   *smf_n4_seid_node;  /* A node of SMF-N4-SEID */

//     ogs_fsm_t       sm;             /* A state machine */
//     struct {
//         bool gx_ccr_init_in_flight; /* Waiting for Gx CCA */
//         uint32_t gx_cca_init_err; /* Gx CCA RXed error code */
//         bool gy_ccr_init_in_flight; /* Waiting for Gy CCA */
//         uint32_t gy_cca_init_err; /* Gy CCA RXed error code */
//         bool gx_ccr_term_in_flight; /* Waiting for Gx CCA */
//         uint32_t gx_cca_term_err; /* Gx CCA RXed error code */
//         bool gy_ccr_term_in_flight; /* Waiting for Gy CCA */
//         uint32_t gy_cca_term_err; /* Gy CCA RXed error code */
//         bool s6b_str_in_flight; /* Waiting for S6B CCA */
//         uint32_t s6b_sta_err; /* S6B CCA RXed error code */
//     } sm_data;

//     bool            epc;            /**< EPC or 5GC */

//     ogs_pfcp_sess_t pfcp;           /* PFCP session context */

//     uint64_t        smpolicycontrol_features; /* SBI features */

//     uint32_t        smf_n4_teid;    /* SMF-N4-TEID is derived from NODE */

//     uint32_t        sgw_s5c_teid;   /* SGW-S5C-TEID is received from SGW */
//     ogs_ip_t        sgw_s5c_ip;     /* SGW-S5C IPv4/IPv6 */

//     uint64_t        smf_n4_seid;    /* SMF SEID is dervied from NODE */
//     uint64_t        upf_n4_seid;    /* UPF SEID is received from Peer */

//     uint32_t        upf_n3_teid;    /* UPF-N3 TEID */
//     ogs_sockaddr_t  *upf_n3_addr;   /* UPF-N3 IPv4 */
//     ogs_sockaddr_t  *upf_n3_addr6;  /* UPF-N3 IPv6 */

//     uint32_t        gnb_n3_teid;    /* gNB-N3 TEID */
//     ogs_ip_t        gnb_n3_ip;      /* gNB-N3 IPv4/IPv6 */

//     char            *gx_sid;        /* Gx Session ID */
//     char            *gy_sid;        /* Gx Session ID */
//     char            *s6b_sid;       /* S6b Session ID */

//     OGS_POOL(pf_precedence_pool, uint8_t);
/*
#define CLEAR_QOS_FLOW_ID(__sESS) \
    do { \
        ogs_assert((__sESS)); \
        smf_qfi_pool_final(__sESS); \
        smf_qfi_pool_init(__sESS); \
    } while(0)
    OGS_POOL(qfi_pool, uint8_t);
    */

//     char            *sm_context_ref; /* smContextRef */
//     uint8_t         psi; /* PDU session identity */
//     uint8_t         pti; /* 5GS-NAS : Procedure transaction identity */

//     char            *sm_context_status_uri; /* SmContextStatusNotification */
//     struct {
//         ogs_sbi_client_t *client;
//     } namf;

//     /* PCF sends the RESPONSE
//      * of [POST] /npcf-smpolocycontrol/v1/policies */
//     char *policy_association_id;

//     OpenAPI_up_cnx_state_e up_cnx_state;

//     /* PLMN ID & NID */
//     ogs_plmn_id_t   plmn_id;

//     /* LTE Location */
//     ogs_eps_tai_t   e_tai;
//     ogs_e_cgi_t     e_cgi;

//     /* NR Location */
//     ogs_5gs_tai_t   nr_tai;
//     ogs_nr_cgi_t    nr_cgi;
//     ogs_time_t      ue_location_timestamp;

//     /* PCF ID */
//     char            *pcf_id;

//     /* Serving NF (AMF) Id */
//     char            *serving_nf_id;

//     /* Integrity protection maximum data rate */
//     struct {
//         uint8_t mbr_dl;
//         uint8_t mbr_ul;
//     } integrity_protection;

//     /* S_NSSAI */
//     ogs_s_nssai_t s_nssai;
//     ogs_s_nssai_t mapped_hplmn;

    /* PDN Configuration */
    ogs_session_t session;
    uint8_t ue_session_type;
    uint8_t ue_ssc_mode;

    char *ipv4;
    char *ipv6;

//     /* RAT Type */
//     uint8_t gtp_rat_type;
//     OpenAPI_rat_type_e sbi_rat_type;

//     struct {
//         uint8_t version; /* GTPC version */
//         ogs_tlv_octet_t ue_pco;
//         ogs_tlv_octet_t ue_epco;
//         ogs_tlv_octet_t user_location_information;
//         ogs_tlv_octet_t ue_timezone;
//         ogs_tlv_octet_t charging_characteristics;
//         bool create_session_response_apn_ambr;
//         bool create_session_response_bearer_qos;
//         uint8_t selection_mode; /* OGS_GTP{1,2}_SELECTION_MODE_*, same in GTPv1C and 2C. */
//         struct {
//             uint8_t nsapi;
//             ogs_gtp1_common_flags_t common_flags;
//             ogs_tlv_octet_t qos; /* Encoded GTPv1C "QoS Profile" IE */
//             ogs_gtp1_qos_profile_decoded_t qos_pdec;
//             bool peer_supports_apn_ambr;
//         } v1;  /* GTPv1C specific fields */
//     } gtp; /* Saved from S5-C/Gn */

//     struct {
//         uint64_t ul_octets;
//         uint64_t dl_octets;
//         ogs_time_t duration;
//         uint32_t reporting_reason; /* OGS_DIAM_GY_REPORTING_REASON_* */
//         /* Snapshot of measurement when last report was sent: */
//         struct {
//             uint64_t ul_octets;
//             uint64_t dl_octets;
//             ogs_time_t duration;
//         } last_report;
//     } gy;

//     struct {
//         ogs_nas_extended_protocol_configuration_options_t ue_epco;
//     } nas; /* Saved from NAS-5GS */

//     struct {
//         ogs_pcc_rule_t  pcc_rule[OGS_MAX_NUM_OF_PCC_RULE];
//         int             num_of_pcc_rule;
//     } policy; /* Saved from N7 or Gx */

//     /* Paging */
//     struct {
//         bool ue_requested_pdu_session_establishment_done;
//         char *n1n2message_location;
//     } paging;

//     /* State */
// #define SMF_NGAP_STATE_NONE                                     0
// #define SMF_NGAP_STATE_DELETE_TRIGGER_UE_REQUESTED              1
// #define SMF_NGAP_STATE_DELETE_TRIGGER_PCF_INITIATED             2
// #define SMF_NGAP_STATE_ERROR_INDICATION_RECEIVED_FROM_5G_AN     3
// #define SMF_NGAP_STATE_DELETE_TRIGGER_SMF_INITIATED             4
//     struct {
//         int pdu_session_resource_release;
//     } ngap_state;

//     /* Handover */
//     struct {
//         bool prepared;
//         bool data_forwarding_not_possible;
//         bool indirect_data_forwarding;

//         /* NG-U UP Transport Information Saved Temporally */
//         uint32_t gnb_n3_teid;
//         ogs_ip_t gnb_n3_ip;

//         /* Indirect DL Forwarding */
//         uint32_t upf_dl_teid;
//         ogs_sockaddr_t *upf_dl_addr;
//         ogs_sockaddr_t *upf_dl_addr6;
//         uint32_t gnb_dl_teid;
//         ogs_ip_t gnb_dl_ip;
//     } handover;

//     /* Charging */
//     struct {
//         uint32_t id;
//     } charging;

//     /* Data Forwarding between the CP and UP functions */
//     ogs_pfcp_pdr_t  *cp2up_pdr;
//     ogs_pfcp_pdr_t  *up2cp_pdr;
//     ogs_pfcp_far_t  *cp2up_far;
//     ogs_pfcp_far_t  *up2cp_far;

//     ogs_list_t      bearer_list;

//     ogs_list_t      pdr_to_modify_list;
//     ogs_list_t      qos_flow_to_modify_list;

//     ogs_gtp_node_t  *gnode;
//     ogs_pfcp_node_t *pfcp_node;

//     smf_ue_t *smf_ue;

//     bool n1_released;
//     bool n2_released;
} OpenAPI_smf_sess_t;

OpenAPI_smf_sess_t *OpenAPI_smf_sess_create(
    ogs_session_t session,
    uint8_t ue_session_type,
    uint8_t ue_ssc_mode,

    char *ipv4,
    char *ipv6

);
void OpenAPI_smf_sess_free(OpenAPI_smf_sess_t *smf_sess);
OpenAPI_smf_sess_t *OpenAPI_smf_sess_parseFromJSON(cJSON *smf_sessJSON);
cJSON *OpenAPI_smf_sess_convertToJSON(OpenAPI_smf_sess_t *smf_sess);
OpenAPI_smf_sess_t *OpenAPI_smf_sess_copy(OpenAPI_smf_sess_t *dst, OpenAPI_smf_sess_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_smf_sess_H_ */

