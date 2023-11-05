/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "test-common.h"

test_ue_t *test_ue_generator(char *suci, char *k_string, char *opc_string)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;

    /* Setup Test UE & Session Context */
    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    test_ue = test_ue_add_by_suci(&mobile_identity_suci, suci);
    ogs_assert(test_ue);

    test_ue->nas.registration.tsc = 0;
    test_ue->nas.registration.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    test_ue->k_string = k_string;
    test_ue->opc_string = opc_string;

    return test_ue;

}

ogs_socknode_t *ue_registration(abts_case *tc, test_ue_t *test_ue, uint32_t gnb_id)
{   
    int rv;
    ogs_socknode_t *ngap;
    ogs_socknode_t *gtpu;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *nasbuf;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;
    ogs_ngap_message_t message;
    int i;


    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    bson_t *doc = NULL;




    ogs_ad("make a socket for gnb");
    /* gNB connects to AMF */
    ngap = testngap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap);
    ogs_ad("gNB socket made to connect to AMF ");

    /* gNB connects to UPF */
    // gtpu = test_gtpu_server(1, AF_INET);
    // ABTS_PTR_NOTNULL(tc, gtpu);

    ogs_ad("Send NG-Setup Reqeust");
    /* Send NG-Setup Reqeust */
    sendbuf = testngap_build_ng_setup_request(gnb_id, 29); // gNB: Hi AMF there is a gNB here!
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ogs_ad("Sent NG-Setup Reqeust");
    
    /* Receive NG-Setup Response */
    ogs_ad("ngap_recv want to receive NG-Setup Response");
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf); // AMF: OK!
    ogs_ad("Received NG-Setup Response: %s", recvbuf->data);

    /********** Insert Subscriber in Database */
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Send Registration request */
    gmmbuf = testgmm_build_registration_request(test_ue, NULL, false, false); // UE: Hey gNB, I have a NAS message in plain text(NAS_5GS_REGISTRATION_REQUEST)for AMF. It contains ngKSI(not important), SUCI, 
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.s1_ue_network_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL, false, false);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf,
                NGAP_RRCEstablishmentCause_mo_Signalling, false, true); // gNB: Hey AMF I have the first NAS from a UE, but I have to wrap it by INITIAL UE MESSAGE. I've allocated a RAN UE NGAP ID for UE.
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ogs_ad("Send Registration request: %s", gmmbuf->data);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_ad("Receive Authentication request");
    /* Receive Authentication request */
    recvbuf = testgnb_ngap_read(ngap); // This line makes the program not to terminate if scp is not initialized
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf); // AMF: hey gNB, I stored your location and built a new profile for the UE. deliver this to UE.It contains autn(and RAND and ngKSI(not important) ) to enable the UE to verify that I'm an honest core, because she will understand that both of us has the same secret k_string
    ogs_ad("Received Authentication request");

    /* Send Authentication response */
    gmmbuf = testgmm_build_authentication_response(test_ue); // UE: OK it's my turn to prove to AUSF that I'm an honest person. I make RES token using RAND and k_string and opc_string(can be derieved from k_string and OP(MNC+MCC) OPc=AES128(Ki,OP) XOR OP).
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    ogs_ad("Send Authentication response : %s", gmmbuf->data);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);// gNB: hey AMF, my UE has a message for you.
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Security mode command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);// AMF: Hey UE let's establish NAS signalling security. and, Please tell me your mobile_identity_imeisv.

    /* Send Security mode complete */
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf); // UE: Got the security config. and Here is my imeisv!
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);//UE: Hey gNB could you pass it to AMF?
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive InitialContextSetupRequest +
     * Registration accept */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf); // AMF:Dear gNB, store Mobility Restriction List in the UE context and execute PDU session configuration and activate security for the UE. Dear UE, here is your GUTI, allowed NSSAI(set of network slices), allowed TAI list(not implemented yet), PDU session status...
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);

    /* Send UE radio capability info indication */
    sendbuf = testngap_build_ue_radio_capability_info_indication(test_ue);// gNB: hey AMF! here are UE radio capability-related information.
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send InitialContextSetupResponse */
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false); //gNB: hey AMF! I made those pdu sessions.
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send Registration complete */
    gmmbuf = testgmm_build_registration_complete(test_ue); // UE: hey AMF I'm done registration.
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Configuration update command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);// AMF, dear UE, I've reset your timer.


    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /* Send PDU session establishment request */
    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", 5);
    ogs_assert(sess);

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 1;

    sess->pdu_session_establishment_param.ssc_mode = 1;
    sess->pdu_session_establishment_param.epco = 1;

    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);


    return ngap;

}


void ue_handover(abts_case *tc, test_ue_t *test_ue, ogs_socknode_t *ngap1, ogs_socknode_t *ngap2, uint32_t gnb_id2)
{   

    int rv;
    ogs_socknode_t *gtpu;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *nasbuf;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;
    ogs_ngap_message_t message;
    int i;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    ogs_com("Send HandoverRequired ");
    /* Send HandoverRequired */
    sendbuf = testngap_build_handover_required(
            test_ue, NGAP_HandoverType_intra5gs,
            gnb_id2, 28,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_com("Receive HandoverRequest ");
    /* Receive HandoverRequest */
    recvbuf = testgnb_ngap_read(ngap2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    ogs_com("Send HandoverRequestAcknowledge");
    /* Send HandoverRequestAcknowledge */
    ogs_list_for_each(&test_ue->sess_list, sess)
        sess->gnb_n3_addr = test_self()->gnb2_addr;

    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap2, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_com("Receive HandoverCommand");
    /* Receive HandoverCommand */
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send UplinkRANStatusTransfer */
    sendbuf = testngap_build_uplink_ran_status_transfer(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive DownlinkRANStatusTransfer */
    recvbuf = testgnb_ngap_read(ngap2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    ogs_com("Send HandoverNotify");
    /* Send HandoverNotify */
    // test_ue->nr_cgi.cell_id = 0x40011;
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap2, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
}




static void test1_func(abts_case *tc, void *data)
{
    ogs_tmp("Test Started!");

    test_ue_t *test_ue = test_ue_generator("0000203190", "465b5ce8b199b49faa5f0a2ee238a6bc", "e8ed289deba952e4283b54e88e6183ca");
    test_ue->nr_cgi.cell_id = 0x40001;
    uint32_t gnb_id = 0x4000;
    ogs_socknode_t *ngap1 = ue_registration(tc, test_ue, gnb_id);

    test_ue_t *test_ue2 = test_ue_generator("0000203192", "465b5ce8b199b49faa5f0a2ee238a6b2", "e8ed289deba952e4283b54e88e6183c2");
    test_ue2->nr_cgi.cell_id = 0x40002;

    uint32_t gnb_id2 = 0x4003;
    ogs_socknode_t *ngap2 = ue_registration(tc, test_ue2, gnb_id2);
    
    test_ue->nr_cgi.cell_id = 0x40025;
    ogs_tmp("handover");
    ue_handover(tc, test_ue, ngap1, ngap2, gnb_id2);
    ogs_msleep(15000);





    // // Set up your sockaddr and socket option
    // ogs_sockaddr_t sa_list;
    // memset(&sa_list, 0, sizeof(sa_list));

    // sa_list.next = NULL;
    // sa_list.ogs_sa_family = AF_INET;  // Assuming IPv4

    // // Fill in the IPv4 address information for your server
    // sa_list.sin.sin_family = AF_INET;
    // sa_list.sin.sin_addr.s_addr = inet_addr("127.0.0.1");  // IP address
    // sa_list.sin.sin_port = htons(6385);  // Port number
    // ogs_sockopt_t socket_option;
    // // Initialize sa_list and socket_option as needed

    // ogs_sock_t *server_socket = ogs_tcp_server(&sa_list, &socket_option);
    // if (!server_socket) {
    //     ogs_tmp("Server creation failed\n");
    //     exit(EXIT_FAILURE);
    // }

    // while (1) {
    //     ogs_sock_t *client_socket = ogs_sock_accept(server_socket);
    //     int BUFFER_SIZE = 128;
    //     char buffer[BUFFER_SIZE];
    //     memset(buffer, 0, BUFFER_SIZE);

    //     // Receive message from client
    //     int bytes_received = ogs_recv(client_socket->fd, buffer, BUFFER_SIZE, 0);
    //     if (bytes_received <= 0) {
    //         ogs_tmp("Error receiving message from client");
    //         ogs_sock_destroy(client_socket);  // Clean up the socket
    //     }
    //     ogs_tmp("ok from client");

    //     char bufferCopy[BUFFER_SIZE];
    //     strncpy(bufferCopy, buffer, BUFFER_SIZE);
    //     char *token = strtok(bufferCopy, " ");
    //     if (strcmp(token, "handover") == 0) {
    //         ogs_tmp("ok1 from client");
    //     } else if (strcmp(token, "ue_generator") == 0) {
    //         char word[20];
    //         char suci[11];
    //         char k_string[33];
    //         char opc_string[33];


    //         if (sscanf(buffer, "%s %s %s %s", word, suci, k_string, opc_string) == 4) {
    //             test_ue_t *test_ue = test_ue_generator(suci, k_string, opc_string);
    //             ogs_ad("UE %s added successfully!", suci);
    //         } else {
    //             ogs_ad("Failed to extract all parts of: %s", buffer);
    //         }

    //     } else {
    //         // Handle other cases
    //     }
    //     close(client_socket->fd);



    //     // pthread_t tid;
    //     // pthread_create(&tid, NULL, client_handler, client_socket_ptr);
    //     // pthread_detach(tid);
    // }

    // // Clean up and close sockets
    // ogs_sock_destroy(server_socket);


    // test_ue->nr_cgi.cell_id = 0x4027;
    // int rv;
    // ogs_socknode_t *gtpu;
    // ogs_pkbuf_t *gmmbuf;
    // ogs_pkbuf_t *gsmbuf;
    // ogs_pkbuf_t *nasbuf;
    // ogs_pkbuf_t *sendbuf;
    // ogs_pkbuf_t *recvbuf;
    // ogs_ngap_message_t message;
    // int i;
    // test_sess_t *sess = NULL;
    // test_bearer_t *qos_flow = NULL;
    // /* Send GMM Status */
    // gmmbuf = testgmm_build_gmm_status(test_ue,
    //         OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED);
    // ABTS_PTR_NOTNULL(tc, gmmbuf);
    // sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    // ABTS_PTR_NOTNULL(tc, sendbuf);
    // ogs_tmp("gmm update");
    // rv = testgnb_ngap_send(ngap1, sendbuf);
    // ABTS_INT_EQUAL(tc, OGS_OK, rv);
    
    // sleep(30);


//     /* Send GTP-U ICMP Packet */
//     qos_flow = test_qos_flow_find_by_qfi(sess, 1);
//     ogs_assert(qos_flow);
//     rv = test_gtpu_send_ping(gtpu, qos_flow, TEST_PING_IPV4);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Send PDUSessionResourceSetupResponse */
//     sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
//     ABTS_PTR_NOTNULL(tc, sendbuf);
//     rv = testgnb_ngap_send(ngap, sendbuf);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Receive GTP-U ICMP Packet */
//     recvbuf = testgnb_gtpu_read(gtpu);
//     ABTS_PTR_NOTNULL(tc, recvbuf);
//     ogs_pkbuf_free(recvbuf);

//     /* Send GTP-U ICMP Packet */
//     rv = test_gtpu_send_ping(gtpu, qos_flow, TEST_PING_IPV4);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Receive GTP-U ICMP Packet */
//     recvbuf = testgnb_gtpu_read(gtpu);
//     ABTS_PTR_NOTNULL(tc, recvbuf);
//     ogs_pkbuf_free(recvbuf);

//     /* Send GTP-U Router Solicitation */
//     rv = test_gtpu_send_slacc_rs(gtpu, qos_flow);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Receive GTP-U Router Advertisement */
//     recvbuf = test_gtpu_read(gtpu);
//     ABTS_PTR_NOTNULL(tc, recvbuf);
//     testgtpu_recv(test_ue, recvbuf);

// #if !defined(__FreeBSD__)
//     /* Send GTP-U ICMP Packet */
//     rv = test_gtpu_send_ping(gtpu, qos_flow, TEST_PING_IPV6);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Receive GTP-U ICMP Packet */
//     recvbuf = test_gtpu_read(gtpu);
//     ABTS_PTR_NOTNULL(tc, recvbuf);
//     ogs_pkbuf_free(recvbuf);
// #endif

//     /* Send UEContextReleaseRequest */
//     sendbuf = testngap_build_ue_context_release_request(test_ue,
//             NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
//             true);
//     ABTS_PTR_NOTNULL(tc, sendbuf);
//     rv = testgnb_ngap_send(ngap, sendbuf);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Receive UEContextReleaseCommand */
//     recvbuf = testgnb_ngap_read(ngap);
//     ABTS_PTR_NOTNULL(tc, recvbuf);
//     testngap_recv(test_ue, recvbuf);
//     ABTS_INT_EQUAL(tc,
//             NGAP_ProcedureCode_id_UEContextRelease,
//             test_ue->ngap_procedure_code);

//     /* Send UEContextReleaseComplete */
//     sendbuf = testngap_build_ue_context_release_complete(test_ue);
//     ABTS_PTR_NOTNULL(tc, sendbuf);
//     rv = testgnb_ngap_send(ngap, sendbuf);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Send De-registration request */
//     gmmbuf = testgmm_build_de_registration_request(test_ue, 1, true, false);
//     ABTS_PTR_NOTNULL(tc, gmmbuf);
//     sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf,
//                 NGAP_RRCEstablishmentCause_mo_Signalling, true, false);
//     ABTS_PTR_NOTNULL(tc, sendbuf);
//     rv = testgnb_ngap_send(ngap, sendbuf);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     /* Receive UEContextReleaseCommand */
//     recvbuf = testgnb_ngap_read(ngap);
//     ABTS_PTR_NOTNULL(tc, recvbuf);
//     testngap_recv(test_ue, recvbuf);
//     ABTS_INT_EQUAL(tc,
//             NGAP_ProcedureCode_id_UEContextRelease,
//             test_ue->ngap_procedure_code);

//     /* Send UEContextReleaseComplete */
//     sendbuf = testngap_build_ue_context_release_complete(test_ue);
//     ABTS_PTR_NOTNULL(tc, sendbuf);
//     rv = testgnb_ngap_send(ngap, sendbuf);
//     ABTS_INT_EQUAL(tc, OGS_OK, rv);

//     ogs_msleep(300);










    /********** Remove Subscriber in Database */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));

//     /* gNB disonncect from UPF */
//     // testgnb_gtpu_close(gtpu);

    /* gNB disonncect from AMF */
    testgnb_ngap_close(ngap1);





        /********** Remove Subscriber in Database */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue2));

// //     /* gNB disonncect from UPF */
// //     testgnb_gtpu_close(gtpu);

    /* gNB disonncect from AMF */
    testgnb_ngap_close(ngap2);

    /* Clear Test UE Context */
    test_ue_remove_all();

    ogs_tmp("Test Finished!");

}

abts_suite *test_ad(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test1_func, NULL);

    return suite;
}
