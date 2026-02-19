#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h> 
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include "constants.h"
#include "auxiliary.h"


#define DEFAULT_PORT "58083" 
#define DEFAULT_IP "127.0.0.1"


int main(int argc, char *argv[]) {
    int fd, errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;
    char buffer[MAXBUF];
    char cmd[1024];

    char *server_ip = DEFAULT_IP;
    char *server_port = DEFAULT_PORT;
    
    // looking for ip and port
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && (i + 1 < argc)) {
            server_ip = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-p") == 0 && (i + 1 < argc)) {
            server_port = argv[i + 1];
            i++;
        }
    }

    // ---- CREATE UDP SOCKET ----
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(1);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    // Resolve udp adress
    errcode = getaddrinfo(server_ip, server_port, &hints, &res);
    if (errcode != 0) {
        fprintf(stderr, "Erro UDP: %s\n", gai_strerror(errcode));
        exit(1);
    }

    printf("User application initialized.\n");

    // prepare server info for tcp
    struct addrinfo *res_tcp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    errcode = getaddrinfo(server_ip, server_port, &hints, &res_tcp);
    if (errcode != 0) {
        fprintf(stderr, "Erro TCP: %s\n", gai_strerror(errcode));
        exit(1);
    }

    // Local storage for session details
    char pass[32] = {0};
    char uid[16] = {0};
    int logged = 0; // 0 = Not logged in, 1 = Logged in

    // ----- MAIN LOOP -----
    while (1) {

        printf("> ");
        fflush(stdout);

        // Read command from stdin 
        if (fgets(cmd, sizeof(cmd), stdin) == NULL)
            break;

        // ---- UPD ----

        // ---- LOGIN ----
        else if (strncmp(cmd, "login", 5) == 0) {

            // Validate input: login UID Password
            // Constraints: UID = 6 digits, Password = 8 alphanumeric chars 
            if (!logged && (sscanf(cmd, "login %s %s", uid, pass) == 2) && 
                check_input(uid,pass)) {

                // Build UDP request: LIN UID password 
                snprintf(buffer, sizeof(buffer), "LIN %s %s\n", uid, pass);

                // Send via UDP
                n = sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
                if (n == -1) {
                    perror("sendto");
                    continue;
                }

                // Receive response
                addrlen = sizeof(addr);
                n = recvfrom(fd, buffer, MAXBUF, 0, (struct sockaddr*)&addr, &addrlen);
                if (n == -1) {
                    perror("recvfrom");
                    continue;
                }

                buffer[n] = '\0'; // Null-terminate string

                // Parse response
                char cmd_resp[10], status[10];
                
                // Check header: RLI status 
                sscanf(buffer, "%s %s", cmd_resp, status);
                
                // Verify protocol tag
                if (strcmp(cmd_resp, "RLI") != 0) {
                    printf("Error: Invalid server response: %s\n", buffer);
                    continue;
                }

                if (!strcmp(status, "OK")) {
                    printf("Login successful.\n"); // 
                    logged = 1;
                }
                else if (!strcmp(status, "REG")) {
                    // REG means new user registered AND logged in 
                    printf("New user registered.\n"); 
                    logged = 1; 
                }
                else if (!strcmp(status, "NOK")) {
                    printf("Error: Incorrect password.\n");
                    memset(pass, 0, sizeof(pass));
                    memset(uid, 0, sizeof(uid)); // 
                }
                else if (!strcmp(status, "ERR")) {
                    printf("Error: Incorrect request message or syntax error.\n"); 
                    memset(pass, 0, sizeof(pass));
                    memset(uid, 0, sizeof(uid));
                }
                else {
                    printf("Unexpected response: %s\n", buffer);
                }

            } else { 
                if (logged){
                    printf("Another user logged in.\n");
                } else {
                // Input validation failure 
                printf("login : invalid parameters\n");
                memset(pass, 0, sizeof(pass));
                memset(uid, 0, sizeof(uid));
                }
            }
        }
        
        // ---- LOGOUT ----
        else if (strncmp(cmd, "logout", 6) == 0) {
            
            // Check local login state first
            if (!logged) {
                printf("logout: User not logged in.\n");
                continue;
            }

            // Build UDP request: LOU UID password 
            snprintf(buffer, sizeof(buffer), "LOU %s %s\n", uid, pass);

            // Send via UDP
            n = sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
            if (n == -1) {
                perror("sendto");
                continue;
            }

            // Receive response
            addrlen = sizeof(addr);
            n = recvfrom(fd, buffer, MAXBUF, 0, (struct sockaddr*)&addr, &addrlen);
            if (n == -1) {
                perror("recvfrom");
                continue;
            }

            buffer[n] = '\0'; // Null-terminate string

            // Parse response
            char cmd_resp[10], status[10];
            sscanf(buffer, "%s %s", cmd_resp, status);

            // Verify protocol tag 
            if (strcmp(cmd_resp, "RLO") != 0) {
                printf("Error: Invalid server response: %s\n", buffer);
                continue;
            }

            if (!strcmp(status, "OK")) {
                printf("Logout successful.\n"); // 
                // Clear local session data
                memset(pass, 0, sizeof(pass));
                memset(uid, 0, sizeof(uid));
                logged = 0;
            } 
            else if (!strcmp(status, "NOK")) {
                printf("Error: User not logged in.\n"); // 
            } 
            else if (!strcmp(status, "WRP")) {
                printf("Error: Incorrect password.\n"); // 
            } 
            else if (!strcmp(status, "UNR")) {
                printf("Error: User not registered.\n"); // 
            } 
            else if (!strcmp(status, "ERR")) {
                printf("Error: Incorrect request message or syntax error.\n"); // 
            } 
            else {
                printf("Unexpected response: %s\n", buffer);
            }
        }

        // ---- UNREGISTER ----
        else if (strncmp(cmd, "unregister", 10) == 0) {
    
            if (!logged) {
                printf("unregister: User not logged in.\n");
                continue;
            }

            // Build UDP request: UNR UID password 
            snprintf(buffer, sizeof(buffer), "UNR %s %s\n", uid, pass);

            // Send via UDP
            n = sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
            if (n == -1) {
                perror("sendto");
                continue;
            }

            // Receive response
            addrlen = sizeof(addr);
            n = recvfrom(fd, buffer, MAXBUF, 0, (struct sockaddr*)&addr, &addrlen);
            if (n == -1) {
                perror("recvfrom");
                continue;
            }

            buffer[n] = '\0'; // Null-terminate string

            // Parse response
            char cmd_resp[10], status[10];
            sscanf(buffer, "%s %s", cmd_resp, status);

            // Verify protocol tag 
            if (strcmp(cmd_resp, "RUR") != 0) {
                printf("Error: Invalid server response: %s\n", buffer);
                continue;
            }

            if (!strcmp(status, "OK")) {
                printf("Unregister successful.\n"); // 
                
                // IMPORTANT: Unregister also performs a logout locally 
                memset(pass, 0, sizeof(pass));
                memset(uid, 0, sizeof(uid));
                logged = 0;
            } 
            else if (!strcmp(status, "NOK")) {
                printf("Error: User not logged in.\n"); // 
            } 
            else if (!strcmp(status, "WRP")) {
                printf("Error: Incorrect password.\n"); // 
            } 
            else if (!strcmp(status, "UNR")) {
                printf("Error: User not registered.\n"); // 
            } 
            else if (!strcmp(status, "ERR")) {
                printf("Error: Incorrect request message or syntax error.\n"); // 
            } 
            else {
                printf("Unexpected response: %s\n", buffer);
            }
        }
       
        // ---- MYEVENTS ---- 
        else if ((strncmp(cmd, "myevents", 8) == 0 || 
          strncmp(cmd, "mye", 3) == 0)) {
              
            if (!logged) {
                printf("Error: User not logged in.\n");
                continue;
            }

            // Build UDP request: LME UID password [cite: 150]
            snprintf(buffer, sizeof(buffer), "LME %s %s\n", uid, pass);

            // Send via UDP
            n = sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
            if (n == -1) {
                perror("sendto");
                continue;
            }
            char buffer[4096];
            struct sockaddr_in addr;
            socklen_t addrlen = sizeof(addr);
            
            n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&addr, &addrlen);

           
            if (n == -1) {
                perror("recvfrom");
                continue;
            }

            buffer[n] = '\0'; // Null-terminate string

            // Parse response
            char cmd_resp[10], status[10];
            
            // Check header: RME status [cite: 152]
            sscanf(buffer, "%s %s", cmd_resp, status);

            // Verify it is an RME response
            if (strcmp(cmd_resp, "RME") != 0) {
                printf("Error: Invalid server response: %s\n", buffer);
                continue;
            }

            if (!strcmp(status, "NOK")) {
                printf("No events created by this user.\n"); // [cite: 153]
            }
            else if (!strcmp(status, "NLG")) {
                printf("Error: User not logged in.\n"); // [cite: 154]
            }
            else if (!strcmp(status, "WRP")) {
                printf("Error: Incorrect password.\n"); // [cite: 159]
            }
            else if (!strcmp(status, "ERR")) {
                printf("Error: Incorrect request message or syntax error.\n"); // [cite: 173]
            }
            else if (!strcmp(status, "OK")) {
                // Status OK means a list follows: EID state EID state ... [cite: 155]
                printf("\n---- My Events ----\n");
                printf("%-5s %-15s\n", "EID", "State");
                printf("--------------------\n");

                char *ptr = buffer;
                
                // Skip "RME" and "OK" to reach the data
                int spaces = 0;
                while (*ptr != '\0' && spaces < 2) {
                    if (*ptr == ' ') spaces++;
                    ptr++;
                }

                // Temporary variables
                char eid[10];
                int state, bytes_read;
                char state_desc[20];
                int count = 0;

                // Parsing loop: read pairs of "EID state"
                while (sscanf(ptr, "%s %d%n", eid, &state, &bytes_read) == 2) {
                    
                    // Decode state codes [cite: 156, 158]
                    switch(state) {
                        case 1: strcpy(state_desc, "Active"); break; // Accepting reservations
                        case 0: strcpy(state_desc, "Past"); break; // Event date passed
                        case 2: strcpy(state_desc, "Sold Out"); break; // Full
                        case 3: strcpy(state_desc, "Closed"); break; // Closed by user
                        default: strcpy(state_desc, "Unknown");
                    }

                    printf("%-5s %-15s\n", eid, state_desc);

                    // Move pointer forward
                    ptr += bytes_read;
                    count++;
                }
                
                if (count == 0) {
                    printf("No valid event data found in OK response.\n");
                }
                printf("\n");
                
            } else {
                printf("Unexpected response: %s\n", buffer);
            }

        }
        
        // ---- MYRESERVATIONS ----
        else if ((strncmp(cmd, "myreservations", 14) == 0 || strncmp(cmd, "myr", 3) == 0)) {
            
            if (!logged) {
                printf("myreservations: User not logged in.\n");
                continue;
            }

            // Preparar buffer de envio
                char request[256];
            snprintf(request, sizeof(request), "LMR %s %s\n", uid, pass);

            // Enviar via UDP
            n = sendto(fd, request, strlen(request), 0, res->ai_addr, res->ai_addrlen);
            if (n == -1) {
                perror("sendto");
                continue;
            }

            // Receber resposta (UDP entrega o datagrama inteiro)
            char buffer[4096];
            struct sockaddr_in addr;
            socklen_t addrlen = sizeof(addr);
            
            n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&addr, &addrlen);

            
            if (n == -1) {
                // Se n for -1 aqui, provavelmente foi Timeout (servidor não respondeu)
                printf("Error: Server response timeout.\n");
                continue;
            }

            buffer[n] = '\0'; // Garante terminação da string

            // Parsing do cabeçalho
            char cmd_resp[10], status[10];
            int offset = 0;
            if (sscanf(buffer, "%s %s%n", cmd_resp, status, &offset) < 2) {
                printf("Error: Invalid server response.\n");
                continue;
            }

            // Validar se é uma resposta RMR
            if (strcmp(cmd_resp, "RMR") != 0) {
                printf("Error: Unexpected protocol response: %s\n", cmd_resp);
                continue;
            }

            // Lógica de Status
            if (!strcmp(status, "NOK")) {
                printf("No reservations found.\n");
            } 
            else if (!strcmp(status, "NLG")) {
                printf("Error: User not logged in.\n");
            } 
            else if (!strcmp(status, "WRP")) {
                printf("Error: Incorrect password.\n");
            } 
            else if (!strcmp(status, "ERR")) {
                printf("Error: Syntax error in request.\n");
            } 
            else if (!strcmp(status, "OK")) {
                
                // Cabeçalho da tabela formatado
                printf("%-5s %-12s %-10s %-6s\n", "EID", "Date", "Time", "Seats");
                printf("---------------------------------------\n");

                // O ponteiro 'ptr' começa logo após o "RMR OK "
                char *ptr = buffer + offset;
                char eid[10], r_date[15], r_time[15], seats[10];
                int bytes_read;
                int count = 0;

                // Loop para ler cada grupo de 4 elementos (EID, Data, Hora, Lugares)
                // O %s no tempo lê "hh:mm:ss" sem problemas
                while (sscanf(ptr, "%s %s %s %s%n", eid, r_date, r_time, seats, &bytes_read) == 4) {
                    
                    printf("%-5s %-12s %-10s %-6s\n", eid, r_date, r_time, seats);
                    
                    ptr += bytes_read; // Avança o ponteiro pelo buffer
                    count++;

                    // Salta espaços e quebras de linha entre as reservas
                    while (*ptr == ' ' || *ptr == '\n' || *ptr == '\r') {
                        ptr++;
                    }
                    
                    if (*ptr == '\0') break; // Chegou ao fim do buffer
                }

                if (count == 0) {
                    printf("No reservation details found in OK response.\n");
                }
                printf("\n");

            } else {
                printf("Unexpected status received: %s\n", status);
            }
        }

        else if (strncmp(cmd, "create", 6) == 0) {
                    char name[16], date[16], hour[10], fname[30]; 
                    int seats;

                    // Validate Input: create name filename date time seats
                    if ((sscanf(cmd, "create %s %s %s %s %d", 
                        name, fname, date, hour, &seats) == 5) &&
                        strlen(name) <= 10 && logged &&
                        isAlnum(name) && 
                        (seats >= 10 && seats <= 999) &&
                        strlen(fname) <= 24 &&
                        isValidDateTime(date, hour)) {

                        // File handling
                        FILE *fp = fopen(fname, "rb");
                        if (!fp) {
                            printf("Error: File not found: %s\n", fname);
                            continue;
                        }

                        long fsize = get_file_size(fp);
                        // Check size limit: Max 10MB
                        if (fsize <= 0 || fsize > 10000000) {
                            fprintf(stderr, "Error: Invalid file size (Max 10MB). Size: %ld\n", fsize);
                            fclose(fp);
                            continue;
                        }

                        unsigned char *fdata = get_file_data(fp, fsize);
                        fclose(fp);
                        
                        if (!fdata) {
                            fprintf(stderr, "Error reading file data.\n");
                            continue;
                        }

                        // TCP connection
                        int tcp_fd_create = socket(AF_INET, SOCK_STREAM, 0);
                        if (tcp_fd_create == -1) {
                            perror("socket");
                            free(fdata);
                            continue;
                        }

                        if (connect(tcp_fd_create, res->ai_addr, res->ai_addrlen) == -1) {
                            perror("connect");
                            close(tcp_fd_create);
                            free(fdata);
                            continue;
                        }

                        // Protocol Message Construction (CRE)
                        // Format: CRE UID pass name date time seats fname fsize data
                        // Note: A space is left after %ld to separate fsize from binary data
                        snprintf(buffer, sizeof(buffer),
                            "CRE %s %s %s %s %s %d %s %ld ",
                            uid, pass, name, date, hour, seats, fname, fsize);

                        // Send Header
                        if (write_all(tcp_fd_create, buffer, strlen(buffer)) < 0) {
                            perror("write header");
                            close(tcp_fd_create);
                            free(fdata);
                            continue;
                        }

                        // Send Binary Data
                        if (write_all(tcp_fd_create, fdata, fsize) < 0) {
                            perror("write data");
                            close(tcp_fd_create);
                            free(fdata);
                            continue;
                        }
                        
                        // Send Protocol Terminator
                        // The message must end with '\n'
                        if (write_all(tcp_fd_create, "\n", 1) < 0) {
                            perror("write terminator");
                            close(tcp_fd_create);
                            free(fdata);
                            continue;
                        }

                        free(fdata); // Data sent, free memory

                        // Receive Response
                        // Shutdown write to indicate we are done sending, wait for response
                        shutdown(tcp_fd_create, SHUT_WR);

                        int n = read_line(tcp_fd_create, buffer, MAXBUF);
                        if (n <= 0) {
                            printf("Error reading server response.\n");
                            close(tcp_fd_create);
                            continue;
                        }

                        close(tcp_fd_create);

                        // Parse Response (RCE)
                        char cmd_resp[10], status[10];
                        
                        // First check: RCE status
                        if (sscanf(buffer, "%s %s", cmd_resp, status) != 2 || strcmp(cmd_resp, "RCE") != 0) {
                            printf("Error: Invalid server response format.\n");
                            continue;
                        }

                        if (!strcmp(status, "OK")) {
                            char eid[10];
                            // If OK, parse the EID
                            if (sscanf(buffer, "%*s %*s %s", eid) == 1) {
                                printf("Event %s created successfully.\n", eid);
                            } else {
                                printf("Event created, but failed to read EID.\n");
                            }
                        }
                        else if (!strcmp(status, "NLG")) {
                            printf("Error: User not logged in.\n"); 
                        }
                        else if (!strcmp(status, "WRP")) {
                            printf("Error: Incorrect password.\n"); 
                        }
                        else if (!strcmp(status, "ERR")) {
                            printf("Error: Incorrect request message or syntax error.\n"); 
                        }
                        else if (!strcmp(status, "NOK")) {
                            printf("Error: Event could not be created.\n");
                        }
                        else {
                            printf("Unexpected response: %s\n", buffer);
                        }

                    } else {
                        printf("create: User not logged-in or invalid parameters\n");
                    }
                }
                
        // ------------ CLOSE ------------  
        else if (strncmp(cmd, "close", 5) == 0) {
            char eid[8];
            
            // Validate input: EID must be 3 digits and user must be logged in
            if ((sscanf(cmd, "close %s", eid) == 1) && strlen(eid) == 3 
                && is_int(eid) && logged) {
                
                // Format message: CLS UID password EID
                snprintf(buffer, sizeof(buffer), "CLS %s %s %s\n", uid, pass, eid);

                // Create TCP socket
                int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (tcp_fd == -1) exit(1);

                if (connect(tcp_fd, res->ai_addr, res->ai_addrlen) == -1) {
                    close(tcp_fd);
                    printf("Error: connect failed.\n");
                    continue;
                }

                // Send request
                if (write_all(tcp_fd, buffer, strlen(buffer)) < 0) {
                    perror("write");
                    close(tcp_fd);
                    continue;
                }

                // Receive response
                int n = read_line(tcp_fd, buffer, MAXBUF);
                if (n <= 0) {
                    printf("Error reading server response.\n");
                    close(tcp_fd);
                    continue;
                }

                close(tcp_fd); 

                // Parse server response
                char cmd_resp[10], status[10];
                
                if (sscanf(buffer, "%s %s", cmd_resp, status) != 2 || strcmp(cmd_resp, "RCL") != 0) {
                    printf("Error: Invalid server response format.\n");
                    continue;
                }

                // Handle status codes
                if (!strcmp(status, "OK"))
                    printf("Event closed successfully.\n"); // 

                else if (!strcmp(status, "NOK"))
                    printf("Error: User does not exist or incorrect password.\n"); // 

                else if (!strcmp(status, "NLG"))
                    printf("Error: User not logged in.\n"); // 

                else if (!strcmp(status, "NOE"))
                    printf("Error: Event does not exist.\n"); // 

                else if (!strcmp(status, "EOW"))
                    printf("Error: Event was not created by the current user.\n"); // 

                else if (!strcmp(status, "SLD"))
                    printf("Error: Event is already sold out.\n"); // 

                else if (!strcmp(status, "PST"))
                    printf("Error: Event date has already passed.\n"); // 

                else if (!strcmp(status, "CLO"))
                    printf("Error: Event was already closed.\n"); // 

                else if (!strcmp(status, "ERR"))
                    printf("Error: Incorrect request message or syntax error.\n"); // 

                else 
                    printf("Unexpected response: %s\n", buffer);

            } else {
                printf("close: User not logged-in or invalid parameters\n");
   
            }
        }
        
        // ----- LIST ---- 
        else if (strncmp(cmd, "list", 4) == 0) {
    snprintf(buffer, sizeof(buffer), "LST\n");

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) { perror("socket"); continue; }

    if (connect(tcp_fd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("connect"); close(tcp_fd); continue;
    }

    if (write_all(tcp_fd, buffer, strlen(buffer)) < 0) {
        perror("write"); close(tcp_fd); continue;
    }

    char chunk[CHUNK_SIZE];
    char storage[CHUNK_SIZE * 2] = ""; // Buffer acumulador
    int storage_len = 0;
    int first_chunk = 1;

    while (1) {
        ssize_t r = read(tcp_fd, chunk, sizeof(chunk));
        if (r < 0) { perror("read"); break; }
        if (r == 0) break; // Fim da ligação

        // Adiciona o que recebeu ao que já tinha guardado
        memcpy(storage + storage_len, chunk, r);
        storage_len += r;
        storage[storage_len] = '\0';

        char *ptr = storage;

        // 1. Processar Header (RLS OK)
        if (first_chunk) {
            if (storage_len < 6) continue; // Espera ter pelo menos "RLS OK"
            
            if (strncmp(ptr, "RLS OK", 6) == 0) {
                ptr += 7; // Pula "RLS OK "
                first_chunk = 0;
            } else if (strncmp(ptr, "RLS NOK", 7) == 0) {
                printf("No events available.\n"); break;
            } else if (strncmp(ptr, "RLS ERR", 7) == 0) {
                printf("Error: Syntax error.\n"); break;
            }
        }

        // 2. Processar Eventos (EID Name State Date Time)
        // Tentamos ler 5 campos. O sscanf retorna quantos leu com sucesso.
        char eid[10], name[50], date[15], time[10], state_code[5];
        int bytes_read;

        // Enquanto conseguirmos ler 5 strings completas...
        while (sscanf(ptr, "%s %s %s %s %s%n", eid, name, state_code, date, time, &bytes_read) == 5) {
            
            int state = atoi(state_code);
            const char *state_str = (state == 1) ? "Active" : (state == 0) ? "Past" : 
                                    (state == 2) ? "Sold Out" : (state == 3) ? "Closed" : "Unknown";

            printf("EID: %s | Name: %-15s | State: %-8s | Date: %s %s\n",
                    eid, name, state_str, date, time);

            ptr += bytes_read;
            // Avança espaços extras
            while (*ptr == ' ') ptr++;
        }

        // 3. Gestão do que sobrou (Fragmento incompleto)
        // Movemos o que não foi processado para o início do storage
        int processed_bytes = ptr - storage;
        int remaining = storage_len - processed_bytes;
        
        if (remaining > 0) {
            memmove(storage, ptr, remaining);
            storage_len = remaining;
        } else {
            storage_len = 0;
        }
        storage[storage_len] = '\0';
    }

    close(tcp_fd);
    printf("\n");
} 
        // ----- SHOW -----
        else if (strncmp(cmd, "show", 4) == 0) {

            char eid[8];
            // Validate input
            if ((sscanf(cmd, "show %s", eid) != 1) || strlen(eid) > 3 || !is_int(eid)) {
                printf("show : Incorrect parameters.\n");
                continue;
            }

            char buffer[MAXBUF];
            // Format command: SED EID
            snprintf(buffer, sizeof(buffer), "SED %s\n", eid);
            // Optional debug: printf("%s", buffer);

            //  TCP: Create socket 
            int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (tcp_fd == -1) {
                perror("socket");
                continue;
            }

            if (connect(tcp_fd, res->ai_addr, res->ai_addrlen) == -1) {
                perror("connect");
                close(tcp_fd);
                continue;
            }

            // Send SED command 
            if (write_all(tcp_fd, buffer, strlen(buffer)) < 0) {
                perror("write");
                close(tcp_fd);
                continue;
            }

            //  Read Initial Response (Header + File Start) 
            ssize_t n = read(tcp_fd, buffer, MAXBUF);
            if (n <= 0) {
                perror("read/server closed");
                close(tcp_fd);
                continue; 
            }

            //  Analyze Response Status 
            char status[10];
            char uid[7], name[20], date[15], time[10], fname[25];
            int attendance, reserved;
            long fsize;
            int header_len = 0;

            // Check status tag first
            sscanf(buffer, "RSE %s", status);

            if (strcmp(status, "NOK") == 0) {
                printf("Error: Event does not exist or server error.\n");
                close(tcp_fd);
                continue;
            } else if (strcmp(status, "ERR") == 0){
                printf("Error: Incorrect request message or invalid values.\n");
                close(tcp_fd);
                continue;
            }
            
            if (strcmp(status, "OK") != 0) {
                printf("Unexpected response: %s\n", buffer);
                close(tcp_fd);
                continue;
            }

            //  Parse Metadata and Fsize
            if (sscanf(buffer, "RSE OK %s %s %s %s %d %d %s %ld%n", 
                uid, name, date, time, &attendance, &reserved, fname, &fsize, &header_len) < 8) {
                printf("Unexpected response: %s\n", buffer);
                close(tcp_fd);
                continue;
            }

            // Prepare and show user event info
            char event_status[10];
            int available = attendance - reserved;
            if (isPastDateTime(date, time)) snprintf(event_status, 10, "Closed");
            else if (available == 0) snprintf(event_status, 10, "Sold out");
            else snprintf(event_status, 10, "Active");

            printf("\n-------- Event Details --------\n\n");
            printf("Owner ID:    %s\n", uid);
            printf("Event ID:    %s\n", eid);
            printf("Status:      %s\n", event_status);
            printf("Date:        %s %s\n\n", date, time);

            printf("Seats: \n");
            
            printf("  Capacity:  %d\n", attendance);
            printf("  Available: %d\n", available);
            printf("  Reserved:  %d\n\n", reserved);
            printf("-------------------------------\n\n");

            //  Pointer Arithmetic (Critical Logic)
            char *data_start = buffer + header_len;
            
            // If the current char is a space, advance 1 byte to reach the actual binary data start
            if (*data_start == ' ') {
                data_start++;
            }

            // Calculate how many bytes of BINARY data are already in the current buffer
            long data_in_buffer = n - (data_start - buffer);

            // ---  Write to File ---
            FILE *f = fopen(fname, "wb");
            if (f == NULL) {
                perror("fopen");
                close(tcp_fd);
                continue;
            }

            // Write the chunk that arrived in the first packet (if any)
            if (data_in_buffer > 0) {
                // Safety: ensure we don't write more than fsize (in case of extra trailing bytes)
                long to_write = (data_in_buffer > fsize) ? fsize : data_in_buffer;
                fwrite(data_start, 1, to_write, f);
            }

            //  Loop to download the rest of the file
            // Initialize total_written with what we just wrote
            long total_written = (data_in_buffer > 0) ? (data_in_buffer > fsize ? fsize : data_in_buffer) : 0;

            while (total_written < fsize) {
                n = read(tcp_fd, buffer, MAXBUF);
                if (n <= 0) break; // Connection error or closed

                // Calculate remaining bytes to avoid writing garbage or protocol terminators
                long bytes_left = fsize - total_written;
                long bytes_to_write = (n < bytes_left) ? n : bytes_left;

                fwrite(buffer, 1, bytes_to_write, f);
                total_written += bytes_to_write;
            }

            fclose(f);
            close(tcp_fd);

            if (total_written == fsize) {
                char cwd[1024];
                getcwd(cwd, sizeof(cwd));
                printf("File %s transferred successfully into %s.\n", fname, cwd);
            } 
            else {
                printf("Transfer error: file incomplete.\n");
            }
        }    
        
        // ---- RESERVE ----  
        else if (strncmp(cmd, "reserve", 7) == 0) {
            char eid[8]; 
            int people;

            // Validate input
            if ((sscanf(cmd, "reserve %s %d", eid, &people) == 2) && strlen(eid) == 3 
                && is_int(eid) && people >= 1 && people <= 999 && logged) {

                // Format Protocol Message
                snprintf(buffer, sizeof(buffer), "RID %s %s %s %d\n", uid, pass, eid, people);

                // TCP: Create Socket 
                int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (tcp_fd == -1) exit(1);

                if (connect(tcp_fd, res->ai_addr, res->ai_addrlen) == -1) {
                    close(tcp_fd);
                    printf("Error: connect failed.\n");
                    continue;
                }

                //  Send via TCP 
                if (write_all(tcp_fd, buffer, strlen(buffer)) < 0) {
                    perror("write");
                    close(tcp_fd);
                    continue;
                }

                //  Receive via TCP 
                int n = read_line(tcp_fd, buffer, MAXBUF);
                if (n <= 0) {
                    printf("Error reading server response.\n");
                    close(tcp_fd);
                    continue;
                }

                close(tcp_fd); // Close connection after response 

                //  Interpret Response 
                char cmd_resp[10], status[10];
                int n_seats = 0;

                if (sscanf(buffer, "%s %s", cmd_resp, status) == 2 && strcmp(cmd_resp, "RRI") == 0) {
                    
                    if (!strcmp(status, "ACC")) {
                        printf("Reservation accepted.\n"); 
                    }
                    else if (!strcmp(status, "NOK")) {
                        printf("Error: Event is not active or does not exist.\n"); 
                    }
                    else if (!strcmp(status, "NLG")) {
                        printf("Error: User not logged in.\n"); 
                    }
                    else if (!strcmp(status, "CLS")) {
                        printf("Error: Event is closed.\n");
                    }
                    else if (!strcmp(status, "SLD")) {
                        printf("Error: Event is sold out.\n"); 
                    }
                    else if (!strcmp(status, "ERR")) {
                        printf("Error: Incorrect request message or syntax error.\n"); }
                    
                    else if (!strcmp(status, "REJ")) {
                    
                        sscanf(buffer, "%*s %*s %d", &n_seats);
                        printf("Reservation rejected. Available seats: %d\n", n_seats);
                    }
                    else if (!strcmp(status, "PST")) {
                        printf("Error: Event date has passed.\n"); 
                    }
                    else if (!strcmp(status, "WRP")) {
                        printf("Error: Incorrect password.\n");
                    }
                    else {
                        printf("Unexpected response: %s\n", buffer);
                    }
                } else {
                    printf("Error: Invalid server response format.\n");
                }

            } else {
                printf("Usage: reserve <EID> <number_of_seats>\n");
                if (!logged) printf("Error: You must be logged in.\n");

            }
        }
       
        // ----- CHANGEPASS ----  
        else if (strncmp(cmd, "changePass", 10) == 0 ){
                char old[12]; char new[12];
                
                // Verify if the input message is correct (length 8, alphanumeric) 
                if ((sscanf(cmd, "changePass %s %s", old, new) == 2) && strlen(old) == 8 
                    && isAlnum(old) && isAlnum(new) && strlen(new) == 8 && logged) {
                    
                    // Format the protocol message: CPS UID oldPassword newPassword 
                    snprintf(buffer, sizeof(buffer), "CPS %s %s %s\n", uid, old, new);

                    // ---------- TCP: create socket ---------- 
                    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (tcp_fd == -1) exit(1);

                    if (connect(tcp_fd, res->ai_addr, res->ai_addrlen) == -1) {
                        close(tcp_fd);
                        printf("Error: connect failed.\n");
                        continue;
                    }

                    // ---------- send via TCP ----------
                    if (write_all(tcp_fd, buffer, strlen(buffer)) < 0) {
                        perror("write");
                        close(tcp_fd);
                        continue;
                    }

                    // ---------- receive via TCP ----------
                    int n = read_line(tcp_fd, buffer, MAXBUF);
                    if (n <= 0) {
                        printf("Error reading server response.\n");
                        close(tcp_fd);
                        continue;
                    }

                    close(tcp_fd); // Close connection after receiving reply

                    // ---------- parse response ----------
                    char status[12];

                    if (sscanf(buffer, "RCP %s", status) == 1) {
                        if (!strcmp(status, "OK")) {
                            printf("Password changed successfully.\n"); // 
                            strcpy(pass, new); // Update local password
                        }
                        else if (!strcmp(status, "NLG")) {
                            printf("Error: User not logged in.\n"); // 
                        }
                        else if (!strcmp(status, "NOK")) {
                            printf("Error: Incorrect old password.\n"); // 
                        }
                        else if (!strcmp(status, "ERR")) {
                            printf("Error: Incorrect request message or syntax error.\n"); 
                        }
                        else if (!strcmp(status, "NID")) {
                            printf("Error: User does not exist.\n"); // 
                        }
                        else {
                            printf("Unexpected response: %s\n", buffer);
                        }
                    } else {
                        printf("Error: Invalid server response.\n");
                    }
                }else 
                    printf("changePass: User not logged-in or invalid parameters\n");

            }
        
        // ---- EXIT ----
        else if (strncmp(cmd, "exit", 4) == 0) {

            if (logged) {
                printf("You must logout before exiting.\n");
                continue;   // NÃO sai
            }

            printf("Exiting client...\n");
            break;          
        }
        else {
            printf("Unknown command: %s", cmd);
            continue;
        }
    }

    freeaddrinfo(res);
    freeaddrinfo(res_tcp);
    close(fd);

    return 0;
}
