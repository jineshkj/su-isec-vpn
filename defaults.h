#ifndef ISEC_DEFAULTS_H
#define ISEC_DEFAULTS_H

#define IVPN_SERV_PORT    55555
#define IVPN_TCP_BACKLOG  128

#define CA_CERT_FILE     "/etc/ivpn/isec-ca.crt"
#define SERVER_CERT_FILE "/etc/ivpn/isec-vpn.crt"
#define SERVER_KEY_FILE  "/etc/ivpn/isec-vpn.key"
#define IVPN_USERS_FILE  "/etc/ivpn/users"
#define IVPN_PAM_SERVICE "system-auth" // "ivpn"

#define IVPN_IV_LENGTH   32 // AES iv length
#define IVPN_KEY_LENGTH  32 // AES key length of 32 bytes = 256 bits
#define IVPN_HMAC_LENGTH 32

#define IVPN_TUNNEL_MTU           16380
#define IVPN_DATA_ENDPOINT_BUFSIZ (16384+4096)

#define MAX_USERNAME 64
#define MAX_PASSWORD 64

#endif // ISEC_DEFAULTS_H
