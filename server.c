#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <signal.h>

#include "constants.h"
#include "auxiliary.h"
#include "client.h"
#include "udp_server.h"
#include "tcp_server.h"

// ./ES [-p ESport] [-v]

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    // Check server mode
    int opt;
    int verbose = 0;
    int port = PORT;

    while ((opt = getopt(argc, argv, "p:v")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p ESport] [-v]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Server directories
    if (mkdir(DIR_ES, 0777) == -1 && errno != EEXIST) {
        perror("Error creating ES directory.");
        exit(1);
    }
    char users_path[MAXDIR];
    snprintf(users_path, MAXDIR, "%s/%s", DIR_ES, DIR_USERS);
    if (mkdir(users_path, 0777) == -1 && errno != EEXIST) {
        perror("Error creating USERS directory.");
        exit(1);
    }
    char events_path[MAXDIR];
    snprintf(events_path, MAXDIR, "%s/%s", DIR_ES, DIR_EVENTS);
    if (mkdir(events_path, 0777) == -1 && errno != EEXIST) {
        perror("Error creating EVENTS directory.");
        exit(1);
    }
    
    // Initialize last_eid.txt
    if (initialize_last_eid_file() == -1) {
        perror("Error initializing last_eid.txt.");
        exit(1);
    }

    fd_set readfds;

    int max_fd;
    int udp_fd, tcp_fd, new_tcp_fd;
    struct sockaddr_in udp_addr, tcp_addr, client_addr;

    ssize_t n;
    socklen_t addrlen; 
    char udp_buffer[MAXBUF];
    char tcp_cmd[4];
    
    //-------------------------- UDP server --------------------------
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_fd == -1) {
        perror("Error in creating UDP socket.");
        exit(1);
    }

    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = INADDR_ANY;
    udp_addr.sin_port = htons(port);

    if (bind(udp_fd, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) == -1) {
        perror("Error in bind UDP.");
        exit(1);
    }

    //-------------------------- TCP server --------------------------
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(tcp_fd == -1) {
        perror("Error in creating TCP socket.");
        exit(1);
    }

    memset(&tcp_addr, 0, sizeof(tcp_addr));
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    tcp_addr.sin_port = htons(port);

    if (bind(tcp_fd, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) == -1) {
        perror("Error in bind TCP.");
        exit(1);
    }

    if (listen(tcp_fd, SOMAXCONN) == -1) {
        perror("Error in listen.");
        exit(1);
    }

    printf("Server is running on UDP and TCP port %d.\n", port);
    max_fd = (udp_fd > tcp_fd) ? udp_fd : tcp_fd;

    //-------------------------- Main loop --------------------------
    while (1) {

        FD_ZERO(&readfds);
        FD_SET(udp_fd, &readfds);
        FD_SET(tcp_fd, &readfds);

        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("Error in select.");
            exit(1);
        }

        // Check for UDP activity
        if (FD_ISSET(udp_fd, &readfds)) {
            addrlen = sizeof(client_addr);

            memset(udp_buffer, 0, MAXBUF);
            n = recvfrom(udp_fd, udp_buffer, MAXBUF - 1, 0,
                         (struct sockaddr *)&client_addr, &addrlen);

            if (n <= 0) {
                perror("Error in recvfrom.");
                continue;
            }

            if (n != 20 || udp_buffer[19] != '\n') {

                if (verbose) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof ip);
                    printf("Invalid UDP message received from:\n");
                    printf("Client IP: %s\nClient Port: %d\n\n", ip, ntohs(client_addr.sin_port));
                }

                sendto(udp_fd, ERR_MSG, strlen(ERR_MSG), 0, (struct sockaddr *)&client_addr, addrlen);
                continue;
            }

            udp_buffer[19] = '\0';
            // printf("Received UDP message: %s\n", udp_buffer);

            handle_udp_message(verbose, udp_fd, udp_buffer, &client_addr, addrlen);
        }

        // Check for TCP activity
        if (FD_ISSET(tcp_fd, &readfds)) {
            addrlen = sizeof(client_addr);

            new_tcp_fd = accept(tcp_fd, (struct sockaddr *)&client_addr, &addrlen);
            if (new_tcp_fd == -1) {
                perror("Error in accept.");
                continue;
            }

            n = recv_all(new_tcp_fd, tcp_cmd, 4);
            if (n == -1) {
                perror("Error in recv.");
                send(new_tcp_fd, ERR_MSG, strlen(ERR_MSG), 0);
                close(new_tcp_fd);
                continue;
            }
            if (n == 0) {
                perror("Client closed the connection immediately.");
                close(new_tcp_fd);
                continue;
            }
            if (tcp_cmd[3] != ' ' && tcp_cmd[3] != '\n') {

                if (verbose) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof ip);
                    printf("Invalid TCP command received from:\n");
                    printf("Client IP: %s\n", ip);
                    printf("Client Port: %d\n", ntohs(client_addr.sin_port));
                }

                send(new_tcp_fd, ERR_MSG, strlen(ERR_MSG), 0);
                close(new_tcp_fd);
                continue;
            }
            
            tcp_cmd[3] = '\0';
            // printf("Received TCP command: %s\n", tcp_cmd);

            handle_tcp_message(verbose, new_tcp_fd, tcp_cmd, &client_addr);
        }
    }
} 