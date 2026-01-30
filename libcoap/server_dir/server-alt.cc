/* minimal CoAP server
 *
 * Copyright (C) 2018-2024 Olaf Bergmann <bergmann@tzi.org>
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <sqlite3.h>
#include "common.hh"
#include <random>
#include <array>

/*
 * This server listens to Unicast CoAP traffic coming in on port 5683 and
 * handles it as appropriate.
 *
 * If support for multicast traffic is not required, comment out the
 * COAP_LISTEN_MCAST_IPV* definitions.
 */

#define COAP_LISTEN_UCAST_IP "::"

#define COAP_LISTEN_MCAST_IPV4 "224.0.1.187"
#define COAP_LISTEN_MCAST_IPV6 "ff02::fd"

std::string pcr_value="0x3FD7F1CEDB997CDB03DC966146B3561270FA35E6959C1E2DCBA80A612746E8D6";
typedef struct valid_cns_t {
  int count;
  char **cn_list;
} valid_cns_t;

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert,
                   size_t asn1_length,
                   coap_session_t *c_session,
                   unsigned depth,
                   int validated,
                   void *arg) {
  valid_cns_t *valid_cn_list = (valid_cns_t *)arg;
  int i;
  /* Remove (void) definition if variable is used */
  (void)asn1_public_cert;
  (void)asn1_length;
  (void)c_session;
  (void)depth;
  (void)validated;

  /* Check that the CN is valid */
  for (i = 0; i < valid_cn_list->count; i++) {
    if (!strcasecmp(cn, valid_cn_list->cn_list[i])) {
      return 1;
    }
  }
  return 1; //Testing: CA always valid
}
typedef struct sni_def_t {
  char *sni;
  coap_dtls_key_t key;
} sni_def_t;

typedef struct valid_snis_t {
  int count;
  sni_def_t *sni_list;
} valid_snis_t;

static coap_dtls_key_t *

verify_pki_sni_callback(const char *sni,
                        void *arg) {
  valid_snis_t *valid_sni_list = (valid_snis_t *)arg;
  int i;

  /* Check that the SNI is valid */
  for (i = 0; i < valid_sni_list->count; i++) {
    if (!strcasecmp(sni, valid_sni_list->sni_list[i].sni)) {
      return &valid_sni_list->sni_list[i].key;
    }
  }
  return NULL;
}

std::array<uint8_t, 16> generate_attestation_nonce() {
    std::random_device rd;
    std::array<uint8_t, 16> nonce{};
    for (auto& b : nonce)
        b = static_cast<uint8_t>(rd());
    return nonce;
}

std::string query_hash_from_db(const std::string &device) {
    sqlite3 *db = nullptr;
    std::string hash;

    if (sqlite3_open("mydb.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open DB: " << sqlite3_errmsg(db) << "\n";
        return "";
    }
    else{
      printf("DB opened\n");
    }

    sqlite3_stmt *stmt;
    std::string sql = "SELECT hash FROM attestation WHERE device = 'device1';";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, device.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            hash = text ? reinterpret_cast<const char*>(text) : "";
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return hash;
}

void get_hash_handler(coap_resource_t *resource,
                      coap_session_t *session,
                      const coap_pdu_t *request,
                      const coap_string_t *query,
                      coap_pdu_t *response) {
    const char* hash = static_cast<const char*>(coap_resource_get_userdata(resource));
    if (!hash) hash = "not found";

    coap_show_pdu(COAP_LOG_INFO, request);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data(response, strlen(hash), reinterpret_cast<const uint8_t*>(hash));
    coap_show_pdu(COAP_LOG_INFO, response);
}


int
main(void) {
  coap_context_t  *ctx = nullptr;
  coap_resource_t *resource = nullptr;
  int result = EXIT_FAILURE;;
  uint32_t scheme_hint_bits;
  coap_addr_info_t *info = nullptr;
  coap_addr_info_t *info_list = nullptr;
  coap_str_const_t *my_address = coap_make_str_const(COAP_LISTEN_UCAST_IP);
  bool have_ep = false;
  if (!coap_dtls_is_supported()) {
    printf("No DTLS support in libcoap!\n");
    return 1;
  }
  else{
    printf("DTLS Supported\n");
  }
   sqlite3 *db = nullptr;

    if(sqlite3_open("mydb.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open DB: " << sqlite3_errmsg(db) << "\n";
        return 1;
    }
    else{
      printf("DB works\n");
    }
    

    sqlite3_stmt *stmt;
   
    std::string hash = query_hash_from_db("device1");
    




sqlite3_finalize(stmt);
sqlite3_close(db);
    sqlite3_finalize(stmt);

    sqlite3_close(db);
  /* Initialize libcoap library */
  coap_startup();

  /* Set logging level */
  coap_set_log_level(COAP_LOG_WARN);
  //coap_set_log_level(COAP_LOG_DEBUG);

  /* Create CoAP context */
  ctx = coap_new_context(nullptr);
    const char *ca_file          = "certs/ca.crt";
    const char *public_cert_file = "certs/server.crt";
    const char *private_key_file = "certs/server.key";

    // Example CN and SNI lists (arrays of strings)
    const char *valid_cn_list[]  = {"coap.device.local", NULL};  // NULL-terminated
    const char *valid_sni_list[] = {"coap.device.local", NULL}; 
  if (!ctx) {
    coap_log_emerg("cannot initialize context\n");
    goto finish;
  }
  //coap_context_set_pki_root_cas(ctx,NULL,NULL);
  coap_context_load_pki_trust_store(ctx);
  coap_dtls_pki_t dtls_pki;
  coap_address_t listen_addr;
  coap_context_set_block_mode(ctx,
                              COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
  memset(&dtls_pki, 0, sizeof(dtls_pki));

  dtls_pki.version                 = COAP_DTLS_PKI_SETUP_VERSION;
  dtls_pki.verify_peer_cert        = 1;
  dtls_pki.check_common_ca         = 1;
  dtls_pki.allow_self_signed       = 1;
  dtls_pki.allow_expired_certs     = 1;
  dtls_pki.cert_chain_validation   = 0;
  dtls_pki.cert_chain_verify_depth = 1;
  dtls_pki.check_cert_revocation   = 1;
  dtls_pki.allow_no_crl            = 1;
  dtls_pki.allow_expired_crl       = 1;
  dtls_pki.allow_bad_md_hash       = 1;
  dtls_pki.allow_short_rsa_length  = 1;
  dtls_pki.is_rpk_not_cert         = 0; /* Set to 1 if RPK */
  //dtls_pki.validate_cn_call_back   = verify_cn_callback;
  dtls_pki.validate_cn_call_back   = NULL;
  //dtls_pki.cn_call_back_arg        = valid_cn_list;
  dtls_pki.cn_call_back_arg        = NULL;
  //dtls_pki.validate_sni_call_back  = verify_pki_sni_callback;
  dtls_pki.validate_sni_call_back  = NULL;
  //dtls_pki.sni_call_back_arg       = valid_sni_list;
  dtls_pki.sni_call_back_arg       = NULL;
  dtls_pki.additional_tls_setup_call_back = NULL;
  dtls_pki.client_sni              = NULL;
  dtls_pki.pki_key.key_type        = COAP_PKI_KEY_PEM;
  dtls_pki.pki_key.key.pem.ca_file = ca_file;
  dtls_pki.pki_key.key.pem.public_cert = public_cert_file;
  dtls_pki.pki_key.key.pem.private_key = private_key_file;

    if (coap_context_set_pki(ctx, &dtls_pki) != 1) {
    coap_log_emerg("Failed to set PKI :<\n");
    coap_free_context(ctx);
    return EXIT_FAILURE;
}
  /* Let libcoap do the multi-block payload handling (if any) */
  coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);

  scheme_hint_bits = coap_get_available_scheme_hint_bits(0, 0, COAP_PROTO_NONE);
  info_list = coap_resolve_address_info(my_address, 0, 0, 0, 0,
                                        0,
                                        scheme_hint_bits, COAP_RESOLVE_TYPE_LOCAL);
  /* Create CoAP listening endpoint(s) */
  coap_address_init(&listen_addr);
  listen_addr.addr.sa.sa_family = AF_INET;
  listen_addr.addr.sin.sin_port = htons(5684);
  for (info = info_list; info != NULL; info = info->next) {
    coap_endpoint_t *ep;
  printf("Nonce1: %u\n",(generate_attestation_nonce()));
  ep = coap_new_endpoint(ctx, &listen_addr, COAP_PROTO_DTLS);
  //ep = coap_new_endpoint(ctx, &listen_addr, COAP_PROTO_DTLS);
  if (!ep) {
    coap_free_context(ctx);
    return NULL;
  }
    if (!ep) {
      coap_log_warn("cannot create endpoint for CoAP proto %u\n",
                    info->proto);
    } else {
      have_ep = true;
    }
  }

  coap_free_address_info(info_list);
  if (have_ep == false) {
    coap_log_err("No context available for interface '%s'\n",
                 (const char *)my_address->s);
    goto finish;
  }

  /* Add in Multicast listening as appropriate */
#ifdef COAP_LISTEN_MCAST_IPV4
  coap_join_mcast_group_intf(ctx, COAP_LISTEN_MCAST_IPV4, NULL);
#endif /* COAP_LISTEN_MCAST_IPV4 */
#ifdef COAP_LISTEN_MCAST_IPV6
  coap_join_mcast_group_intf(ctx, COAP_LISTEN_MCAST_IPV6, NULL);
#endif /* COAP_LISTEN_MCAST_IPV6 */

  /* Create a resource that the server can respond to with information */
  resource = coap_resource_init(coap_make_str_const("test"), 0);
  coap_register_handler(resource, COAP_REQUEST_GET,
                        [](auto, auto,
                           const coap_pdu_t *request,
                           auto, coap_pdu_t *response) {
                           coap_show_pdu(COAP_LOG_WARN, request);
                           coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
                           coap_add_data(response, 25,
                                        (const uint8_t *)"Test przeszedl pomyslnie");
                           coap_show_pdu(COAP_LOG_WARN, response);
                         });
  coap_add_resource(ctx, resource);

  /* Create another resource that the server can respond to with information */
  resource = coap_resource_init(coap_make_str_const("hello/my"), 0);
  coap_register_handler(resource, COAP_REQUEST_GET,
                        [](auto, auto,
                           const coap_pdu_t *request,
                           auto, coap_pdu_t *response) {
                           coap_show_pdu(COAP_LOG_WARN, request);
                           coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
                           coap_add_data(response, 8,
                                         (const uint8_t *)"my world");
                           coap_show_pdu(COAP_LOG_WARN, response);
                         });
  coap_add_resource(ctx, resource);
  
  resource = coap_resource_init(coap_make_str_const("throngler"), 0);
  coap_register_handler(resource, COAP_REQUEST_GET,
                        [](auto, auto,
                           const coap_pdu_t *request,
                           auto, coap_pdu_t *response) {
                           coap_show_pdu(COAP_LOG_WARN, request);
                           coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
                           coap_add_data(response, 16,
                                         (const uint8_t *)"Im throngling it");
                           coap_show_pdu(COAP_LOG_WARN, response);
                         });
  resource = coap_resource_init(coap_make_str_const("hash"), 0);
  
  

    // Create the resource
    
    coap_resource_set_userdata(resource, (void*)hash.c_str());
    coap_register_handler(resource, COAP_REQUEST_GET, get_hash_handler);
    coap_add_resource(ctx, resource);
resource = coap_resource_init(coap_make_str_const("pcr_check"), 0);
coap_register_handler(resource, COAP_REQUEST_PUT, 
    [](auto, auto, const coap_pdu_t *request, auto, coap_pdu_t *response) {
        coap_show_pdu(COAP_LOG_WARN, request);
        
        // Get the incoming data from the request
        size_t data_len = 0;
        const uint8_t *data = nullptr;
        coap_get_data(request, &data_len, &data);
        
        // Convert incoming data to string for comparison
        std::string incoming_pcr(reinterpret_cast<const char*>(data), data_len);
        
        // Compare with local pcr_value
        if (incoming_pcr == pcr_value) {
            // Match found
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
            coap_add_data(response, 40, (const uint8_t *)"PCR Values Match, Attestation Completed");
        } else {
            // No match
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
            coap_add_data(response, 29, (const uint8_t *)"No Match, Attestation Failed");
        }
        
        coap_show_pdu(COAP_LOG_WARN, response);
    });
coap_add_resource(ctx, resource);
  /* Handle any libcoap I/O requirements */
  while (true) {
    coap_io_process(ctx, COAP_IO_WAIT);
  }

  result = EXIT_SUCCESS;
finish:

  coap_free_context(ctx);
  coap_cleanup();

  return result;
}
