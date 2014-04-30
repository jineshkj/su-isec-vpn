#ifndef ISEC_DEFAULTS_H
#define ISEC_DEFAULTS_H

#define IVPN_SERV_PORT    55555
#define IVPN_TCP_BACKLOG  128

#define CA_CERT_FILE     "/etc/ivpn/isec-ca.crt"
#define SERVER_CERT_FILE "/etc/ivpn/isec-vpn.crt"
#define SERVER_KEY_FILE  "/etc/ivpn/isec-vpn.key"

#define IVPN_IV_LENGTH   32 // AES iv length of 16 bytes = 128 bits
#define IVPN_KEY_LENGTH  32 // AES key length of 32 bytes = 256 bits

#endif // ISEC_DEFAULTS_H
