/* minimal CoAP PKI client
 *
 * Based on libcoap examples, modified for DTLS + PKI mutual authentication.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "common.hh"


static int have_response = 0;

#ifndef COAP_CLIENT_URI
#define COAP_CLIENT_URI "coaps://10.204.29.130/pcr_check"
#endif



#include "common.hh"
#include <openssl/provider.h>

static int list_loaded_cb(OSSL_PROVIDER *provider, void *cbdata) {
    const char *name = OSSL_PROVIDER_get0_name(provider);  // Try get0 instead of just name
    printf("  - %s (LOADED)\n", name);
    return 1;
}

void list_loaded_providers(void) {
    printf("Currently LOADED providers:\n");
    OSSL_PROVIDER_do_all(NULL, list_loaded_cb, NULL);
}
int
resolve_address(coap_str_const_t *host, uint16_t port, coap_address_t *dst,
                int scheme_hint_bits) {
  int ret = 0;
  coap_addr_info_t *addr_info;

  addr_info = coap_resolve_address_info(host, port, port,  port, port,
                                        AF_UNSPEC, scheme_hint_bits,
                                        COAP_RESOLVE_TYPE_REMOTE);
  if (addr_info) {
    ret = 1;
    *dst = addr_info->addr;
  }

  coap_free_address_info(addr_info);
  return ret;
}
int main(int argc, char *argv[]) {
  coap_context_t *ctx = nullptr;
  OSSL_PROVIDER *tpm2_prov;
  coap_session_t *session = nullptr;
  coap_optlist_t *optlist = nullptr;
  coap_address_t dst;
  coap_pdu_t *pdu = nullptr;
  int result = EXIT_FAILURE;
  int len;
  int res;
  unsigned int wait_ms;
  coap_uri_t uri;
  const char *coap_uri = COAP_CLIENT_URI;
  int is_mcast;
#define BUFSIZE 100
  unsigned char scratch[BUFSIZE];
    list_loaded_providers();
  if (argc > 1)
    coap_uri = argv[1];

  if (!coap_dtls_is_supported()) {
    printf("No DTLS support in libcoap!\n");
    return 1;
  } else {
    printf("DTLS Supported\n");
    coap_show_tls_version(COAP_LOG_WARN);
  }

  coap_startup();
  coap_set_log_level(COAP_LOG_INFO);
  //coap_set_log_level(COAP_LOG_DEBUG);

  const char *ca_file          = "certs/ca.crt";
  const char *public_cert_file = "certs/client-dev.crt";
  //const char *private_key_file = "certs/client-dev.key";
  const char *private_key_pem_buf = getenv("UNENCRYPTED_KEY");

  // Get PCR value to send
  const char *pcr_value = getenv("PCR1");
  printf("Sending PCR value: %s\n", pcr_value);

  /* Parse the URI */
  len = coap_split_uri((const unsigned char *)coap_uri, strlen(coap_uri), &uri);
  if (len != 0) {
    coap_log_warn("Failed to parse URI: %s\n", coap_uri);
    goto finish;
  }

  /* Resolve destination */
  len = resolve_address(&uri.host, uri.port, &dst, 1 << uri.scheme);
  if (len <= 0) {
    coap_log_warn("Failed to resolve address %*.*s\n",
                  (int)uri.host.length, (int)uri.host.length, (const char *)uri.host.s);
    goto finish;
  }

  is_mcast = coap_is_mcast(&dst);

  /* Create CoAP context */
  ctx = coap_new_context(nullptr);
  if (!ctx) {
    coap_log_emerg("cannot create libcoap context\n");
    goto finish;
  }

  coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

  /* === PKI SETUP === */
  coap_dtls_pki_t dtls_pki;
  memset(&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version                 = COAP_DTLS_PKI_SETUP_VERSION;
  dtls_pki.verify_peer_cert        = 1;   // verify server certificate
  dtls_pki.check_common_ca         = 1;   // ensure CA match
  dtls_pki.allow_self_signed       = 1;   // allow if testing
  dtls_pki.allow_expired_certs     = 0;
  dtls_pki.cert_chain_validation   = 0;
  dtls_pki.cert_chain_verify_depth = 2;
  dtls_pki.check_cert_revocation   = 0;
  dtls_pki.allow_no_crl            = 1;
  dtls_pki.client_sni              = NULL;
  dtls_pki.validate_sni_call_back  = NULL;
  dtls_pki.validate_cn_call_back   = NULL;
  dtls_pki.cn_call_back_arg        = NULL;
  dtls_pki.allow_expired_crl       = 1;

  // dtls_pki.pki_key.key_type            = COAP_PKI_KEY_PEM;
  // dtls_pki.pki_key.key.pem.ca_file     = ca_file;
  // dtls_pki.pki_key.key.pem.public_cert = public_cert_file;
  // dtls_pki.pki_key.key.pem.private_key = private_key_file;
  dtls_pki.pki_key.key_type            = COAP_PKI_KEY_DEFINE;
  
  dtls_pki.pki_key.key.define.ca_def          = COAP_PKI_KEY_DEF_PEM;      /* CA from PEM file */
  dtls_pki.pki_key.key.define.public_cert_def = COAP_PKI_KEY_DEF_PEM;      /* Cert from PEM file */
  dtls_pki.pki_key.key.define.private_key_def = COAP_PKI_KEY_DEF_PEM_BUF;  /* Private key from PEM buffer */

  dtls_pki.pki_key.key.pem.ca_file     = ca_file;
  dtls_pki.pki_key.key.pem.public_cert = public_cert_file;
  dtls_pki.pki_key.key.pem.private_key = private_key_pem_buf;
  dtls_pki.pki_key.key.pem_buf.private_key_len = strlen(private_key_pem_buf);



  // Optional: SNI (server hostname)
  dtls_pki.client_sni = (char *)uri.host.s;

  /* Create DTLS session */
  if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
    session = coap_new_client_session_pki(ctx, NULL, &dst,
                                          COAP_PROTO_DTLS, &dtls_pki);
  } else if (uri.scheme == COAP_URI_SCHEME_COAP) {
    session = coap_new_client_session(ctx, NULL, &dst, COAP_PROTO_UDP);
  } else {
    coap_log_warn("Unsupported URI scheme\n");
    goto finish;
  }

  if (!session) {
    coap_log_emerg("Cannot create client session\n");
    goto finish;
  }

  /* Response handler */
  coap_register_response_handler(ctx,
    [](auto, auto, const coap_pdu_t *received, auto) {
      size_t len;
      const uint8_t *databuf;
      size_t offset;
      size_t total;
      have_response = 1;
      coap_show_pdu(COAP_LOG_INFO, received);
      if (coap_get_data_large(received, &len, &databuf, &offset, &total)) {
        printf("Server response: ");
        fwrite(databuf, 1, len, stdout);
        fwrite("\n", 1, 1, stdout);
      }
      return COAP_RESPONSE_OK;
    });

  /* Build PUT request */
  pdu = coap_pdu_init(is_mcast ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
                      COAP_REQUEST_CODE_PUT,  // Changed from GET to PUT
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (!pdu) {
    coap_log_emerg("Cannot create PDU\n");
    goto finish;
  }

  /* Add URI options */
  len = coap_uri_into_options(&uri, &dst, &optlist, 1, scratch, sizeof(scratch));
  if (len) {
    coap_log_warn("Failed to create URI options\n");
    goto finish;
  }

  if (optlist && !coap_add_optlist_pdu(pdu, &optlist)) {
    coap_log_warn("Failed to add options to PDU\n");
    goto finish;
  }

  /* Add PCR value as payload data */
  if (!coap_add_data(pdu, strlen(pcr_value), 
                     (const uint8_t *)pcr_value)) {
    coap_log_warn("Failed to add data to PDU\n");
    goto finish;
  }

  coap_show_pdu(COAP_LOG_INFO, pdu);

  /* Send request */
  if (coap_send(session, pdu) == COAP_INVALID_MID) {
    coap_log_err("cannot send CoAP PDU\n");
    goto finish;
  }

  wait_ms = (coap_session_get_default_leisure(session).integer_part + 1) * 1000;

  /* Wait for response */
  while (have_response == 0 || is_mcast) {
    res = coap_io_process(ctx, 1000);
    if (res >= 0) {
      if (wait_ms > 0) {
        if ((unsigned)res >= wait_ms) {
          fprintf(stdout, "timeout\n");
          break;
        } else {
          wait_ms -= res;
        }
      }
    }
  }

  result = EXIT_SUCCESS;

finish:
  coap_delete_optlist(optlist);
  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();
  return result;
}