#ifndef ISEC_ERROR_H
#define ISEC_ERROR_H

/* define various exit errors */

#define EXIT_OK           0
#define EXIT_CLIOPT_ERR   1  // error in parsing cli arguments
#define EXIT_PASSWORD     2  // error in reading password from user
#define EXIT_AUTH_ERROR   3  // exit due to authentication error
#define EXIT_TCP_ERROR    4  // error in tcp communication channel

#endif // ISEC_ERROR_H
