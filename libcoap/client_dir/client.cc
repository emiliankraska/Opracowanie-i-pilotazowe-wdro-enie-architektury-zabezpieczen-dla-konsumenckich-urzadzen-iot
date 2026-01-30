/* minimal CoAP PKI client
 *
 * Based on libcoap examples, modified for DTLS + PKI mutual authentication.
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>

#include "common.hh"

static int have_response = 0;
static char received_nonce[65] = {0}; // Buffer for nonce (32 hex chars + potential extra)

#ifndef COAP_CLIENT_URI
#define COAP_CLIENT_URI "coaps://127.0.0.1/attestation_request"
#endif

int main(int argc, char *argv[]) {
  coap_context_t *ctx = nullptr;
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
  const char *public_cert_file = "certs/client.crt";
  const char *private_key_file = "certs/client.key";

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

  dtls_pki.pki_key.key_type            = COAP_PKI_KEY_PEM;
  dtls_pki.pki_key.key.pem.ca_file     = ca_file;
  dtls_pki.pki_key.key.pem.public_cert = public_cert_file;
  dtls_pki.pki_key.key.pem.private_key = private_key_file;

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
        // Copy the nonce to global buffer
        if (len < sizeof(received_nonce)) {
          memcpy(received_nonce, databuf, len);
          received_nonce[len] = '\0';
          
          printf("\n=== ATTESTATION NONCE RECEIVED ===\n");
          printf("Nonce (hex): %s\n", received_nonce);
          printf("Length: %zu bytes\n", len);
          printf("==================================\n\n");
        } else {
          printf("Nonce too large!\n");
        }
      }
      return COAP_RESPONSE_OK;
    });

  /* Build request */
  pdu = coap_pdu_init(is_mcast ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
                      COAP_REQUEST_CODE_GET,
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