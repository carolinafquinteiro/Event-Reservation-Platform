#include <netinet/in.h>

void handle_tcp_message(int verbose, int tcp_fd, char *cmd, struct sockaddr_in *client_addr);
int handle_event_creation(int verbose, int tcp_fd);
int handle_event_closure(int verbose, int tcp_fd);
int handle_events_listing(int tcp_fd);
int handle_event_show(int tcp_fd);
int handle_event_reservation(int verbose, int tcp_fd);
int handle_change_password(int verbose, int tcp_fd);
