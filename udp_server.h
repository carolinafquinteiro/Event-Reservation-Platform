#include <unistd.h>

void handle_udp_message( int verbose, int udp_fd, char *buffer, struct sockaddr_in *client_addr, socklen_t addrlen);
