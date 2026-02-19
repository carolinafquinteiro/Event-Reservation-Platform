#include <stdio.h>      
#include <stdlib.h>     
#include <string.h>     
#include <unistd.h>     
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>  
#include <netdb.h>     
#include <sys/stat.h>  
#include <dirent.h>     
#include <ctype.h>
#include <time.h>

#include "client.h"
#include "constants.h"
#include "udp_server.h"
#include "auxiliary.h"


// reservation struct for sorting in LMR
typedef struct {
    char eid[8];
    char date[11];
    char time[9];
    char reserved[8];
    time_t ts;
} rsv_t;

static int rsv_cmp(const void *a, const void *b) {
    const rsv_t *ra = a;
    const rsv_t *rb = b;
    if (ra->ts < rb->ts) return 1;
    if (ra->ts > rb->ts) return -1;
    return 0;
}

void handle_udp_message(int verbose, int udp_fd, char *buffer, struct sockaddr_in *client_addr, socklen_t addrlen) {

    char cmd[10] = {0}; 
    char uid[10] = {0};
    char pass[10] = {0};
    char response[4096] = {0}; 

    int num_tokens = sscanf(buffer, "%3s %6s %8s", cmd, uid, pass);
    int input_ok = check_input(uid, pass);

    //----   LOGIN -----
   if (strcmp(cmd, "LIN") == 0) {
        if (num_tokens != 3 && !input_ok) {
            snprintf(response, sizeof(response), "RLI ERR\n");
        } else {
            // Define file paths
            char user_dir[100];
            char pass_file[128];
            char login_file[128];
            char created_dir[128];
            char reserved_dir[128];

            snprintf(user_dir, sizeof(user_dir), "%s/%s/%s", DIR_ES, DIR_USERS, uid);
            snprintf(pass_file, sizeof(pass_file), "%s/%s_pass.txt", user_dir, uid);
            snprintf(login_file, sizeof(login_file), "%s/%s_login.txt", user_dir, uid);
            snprintf(created_dir, sizeof(created_dir), "%s/CREATED", user_dir);
            snprintf(reserved_dir, sizeof(reserved_dir), "%s/RESERVED", user_dir);

            // Check if the user already exists
            if (exists(user_dir) && exists(pass_file)) {
                // --- USER EXISTS (LOGIN ATTEMPT) ---

                int check = check_password(pass, pass_file);

                if (check == 1) {
                    FILE *fl = fopen(login_file, "w");
                        if (fl) {
                            fprintf(fl, "Logged in\n"); 
                            fclose(fl);
                            snprintf(response, sizeof(response), "RLI OK\n");
                        } else {
                            snprintf(response, sizeof(response), "RLI ERR\n"); // Error creating login file
                        }

                } else if (check == 2) {
                    snprintf(response, sizeof(response), "RLI NOK\n"); // Wrong password

                }else {
                    snprintf(response, sizeof(response), "RLI ERR\n"); // Empty password file
                }
            }

            else {
                // --- NEW USER (REGISTRATION) ---
                int can_create_files = 1; // Flag to control flow

                // 1. Check if directory exists
                if (!exists(user_dir)) {
                    
                    // Try to create directory
                    if (mkdir(user_dir, 0700) == 0) {
                        // Success creating main dir, create sub-dirs
                        mkdir(created_dir, 0700); 
                        mkdir(reserved_dir, 0700); 
                        
                    } else {
                        // Failed to create directory
                        perror("Error in mkdir user");
                        snprintf(response, sizeof(response), "RLI ERR\n"); 
                        can_create_files = 0; // Stop here
                    }
                } 
                // Only proceed if the directory is ready (created now or existed before)
                if (can_create_files) {
                    
                    // Create password file
                    FILE *fp = fopen(pass_file, "w");
                    if (fp) {
                        fprintf(fp, "%s", pass);
                        fclose(fp);

                        // Create login file
                        FILE *fl = fopen(login_file, "w");
                        if (fl) {
                            fprintf(fl, "Logged in\n");
                            fclose(fl);
                            snprintf(response, sizeof(response), "RLI REG\n");
                        } else {
                            snprintf(response, sizeof(response), "RLI ERR\n"); // Failed to create login file
                        }
                    } else {
                        snprintf(response, sizeof(response), "RLI ERR\n"); // Failed to create pass file
                    }
                }
            }
        }
    }

    // ------  LOGOUT ------
    else if (strcmp(cmd, "LOU") == 0) {
        if (num_tokens != 3 && !input_ok) {
            snprintf(response, sizeof(response), "RLO ERR\n");
        } else {
            char user_dir[100];
            char pass_file[128];
            char login_file[128];
            
            snprintf(user_dir, sizeof(user_dir), "%s/%s/%s", DIR_ES, DIR_USERS, uid);
            snprintf(pass_file, sizeof(pass_file), "%s/%s_pass.txt", user_dir, uid);
            snprintf(login_file, sizeof(login_file), "%s/%s_login.txt", user_dir, uid);

            // Check if user exists
                if (!exists(user_dir) || !exists(pass_file)) {
                snprintf(response, sizeof(response), "RLO UNR\n"); // User not registered
            } else {

                int pass_ok = check_password(pass, pass_file);
                
                if (pass_ok == 2) {
                    snprintf(response, sizeof(response), "RLO WRP\n"); // Wrong password
                } else if (pass_ok == 1 && !exists(login_file)) {
                    snprintf(response, sizeof(response), "RLO NOK\n"); // User not logged in
                } else {
                    // Delete login.txt file (Perform logout)
                    if (unlink(login_file) == 0) {
                        snprintf(response, sizeof(response), "RLO OK\n");
                    } else {
                        snprintf(response, sizeof(response), "RLO ERR\n");
                    }
                }
            }
        }
    }
    
    // ----- UNREGISTER ------
    else if (strcmp(cmd, "UNR" ) == 0) {
            if (num_tokens != 3 && !input_ok) {
                snprintf(response, sizeof(response), "RUR ERR\n");
            } else {
                char user_dir[100];
                char pass_file[128];
                char login_file[128];
                
                snprintf(user_dir, sizeof(user_dir), "%s/%s/%s", DIR_ES, DIR_USERS, uid);
                snprintf(pass_file, sizeof(pass_file), "%s/%s_pass.txt", user_dir, uid);
                snprintf(login_file, sizeof(login_file), "%s/%s_login.txt", user_dir, uid);

                // Check if user exists
                if (!exists(user_dir) || !exists(pass_file)) {
                    snprintf(response, sizeof(response), "RUR UNR\n"); // User not registered
                
                // Check if user is logged
                }else if(!exists(login_file)) {
                    snprintf(response, sizeof(response), "RUR NOK\n"); // User not logged in

                }
                else {
                    // Check password
                    int pass_ok = check_password(pass, pass_file);

                    if (pass_ok == 2) {
                        snprintf(response, sizeof(response), "RUR WRP\n"); // Wrong password
                    }else if (pass_ok) {
                        // Delete login.txt file (Perform logout)
                        if (unlink(login_file) == 0 && unlink(pass_file) == 0) {
                            snprintf(response, sizeof(response), "RUR OK\n");
                        } else {
                            snprintf(response, sizeof(response), "RUR ERR\n");
                        }
                    }else  snprintf(response, sizeof(response), "RUR ERR\n");
                }
            }
        }// Comando desconhecido
     
    // ------ MYEVENTS ------
    else if (strcmp(cmd, "LME") == 0) {
        if (num_tokens != 3 && !input_ok) {
            snprintf(response, sizeof(response), "RME ERR\n");
        } else {
            char user_dir[100];
            char pass_file[128];
            char login_file[128];
            char created_dir[128];
            
            snprintf(user_dir, sizeof(user_dir), "%s/%s/%s", DIR_ES, DIR_USERS, uid);
            snprintf(pass_file, sizeof(pass_file), "%s/%s_pass.txt", user_dir, uid);
            snprintf(login_file, sizeof(login_file), "%s/%s_login.txt", user_dir, uid);
            snprintf(created_dir, sizeof(created_dir), "%s/CREATED", user_dir);

            // Check if user exists
            if (!exists(user_dir) || !exists(pass_file)) {
                sprintf(response, "RME ERR\n"); // User not registered
            } 
            // User exists
            else {
                // Check password
                int pass_ok = check_password(pass, pass_file);
                
                if (pass_ok==2) {
                    snprintf(response, sizeof(response), "RME WRP\n"); // Wrong password
                } else if (!exists(login_file)) {
                    snprintf(response, sizeof(response), "RME NLG\n"); // User not logged in
                } else {
                    DIR *d = opendir(created_dir);
                    struct dirent *dir;
                    int eids[MAX_EID + 1];
                    int ecnt = 0;
                    char buff_response[2048] = {};

                    if (d) {
                        // Collect EIDs from CREATED directory
                        while ((dir = readdir(d)) != NULL) {
                            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
                            char eid_s[16];
                            strncpy(eid_s, dir->d_name, sizeof(eid_s));
                            eid_s[sizeof(eid_s)-1] = '\0';
                            char *dot = strrchr(eid_s, '.');
                            if (dot) *dot = '\0';
                            int eid_i = atoi(eid_s);
                            if (eid_i > 0 && ecnt < (MAX_EID + 1)) {
                                eids[ecnt++] = eid_i;
                            }
                        }
                        closedir(d);
                    }

                    if (ecnt == 0) {
                        snprintf(response, sizeof(response), "RME NOK\n");
                    } else {
                        // Sort ascending (simple insertion sort) then reverse for descending
                        for (int i = 1; i < ecnt; i++) {
                            int key = eids[i];
                            int j = i - 1;
                            while (j >= 0 && eids[j] > key) {
                                eids[j + 1] = eids[j];
                                j--;
                            }
                            eids[j + 1] = key;
                        }
                        /* keep ascending order (001, 002, ...) */

                        // Build response in sorted (descending) order
                        for (int idx = 0; idx < ecnt; idx++) {
                            int eid_i = eids[idx];
                            char eid[8];
                            snprintf(eid, sizeof(eid), "%03d", eid_i);

                            char event_dir[100];
                            char start_file[128];
                            char res_file[128];
                            char end_file[128];
                            char state[4] = "0";

                            snprintf(event_dir, sizeof(event_dir), "%s/%s/%s", DIR_ES, DIR_EVENTS, eid);
                            snprintf(start_file, sizeof(start_file), "%s/START_%s.txt", event_dir, eid);
                            snprintf(res_file, sizeof(res_file), "%s/RES_%s.txt", event_dir, eid);
                            snprintf(end_file, sizeof(end_file), "%s/END_%s.txt", event_dir, eid);

                            if (exists(end_file)) {
                                strcpy(state, "3");
                            } else {
                                FILE *fp = fopen(start_file, "r");
                                if (fp) {
                                    char s_uid[7], s_name[50], file_name[50], s_date[11], s_time[6];
                                    int s_attend = 0;
                                    if (fscanf(fp, "%6s %50s %50s %d %10s %5s", s_uid, s_name, file_name, &s_attend, s_date, s_time) == 6) {
                                        if (!isfutureTime(s_date, s_time)) {
                                            strcpy(state, "0");
                                        } else {
                                            FILE *fr = fopen(res_file, "r");
                                            if (fr) {
                                                int reserved = 0;
                                                fscanf(fr, "%d", &reserved);
                                                fclose(fr);
                                                if (s_attend <= reserved) strcpy(state, "2");
                                                else strcpy(state, "1");
                                            }
                                        }
                                    }
                                    fclose(fp);
                                }
                            }

                            char item[32];
                            snprintf(item, sizeof(item), " %s %s", eid, state);
                            if (strlen(buff_response) + strlen(item) < sizeof(buff_response) - 1) {
                                strncat(buff_response, item, sizeof(buff_response) - strlen(buff_response) - 1);
                            }
                        }

                        snprintf(response, sizeof(response), "RME OK%s\n", buff_response);
                    }
                }
            }
        }
    }
    
    // ------------ MYRESERVATIONS  ------------
    else if (strcmp(cmd, "LMR") == 0) {
        // Input validation (UID and password)
        if (num_tokens != 3) {
            snprintf(response, sizeof(response), "RMR ERR\n");
        } else {
            char user_dir[100], pass_file[128], login_file[128], reserved_dir[128];
            
            snprintf(user_dir, sizeof(user_dir), "%s/%s/%s", DIR_ES, DIR_USERS, uid);
            snprintf(pass_file, sizeof(pass_file), "%s/%s_pass.txt", user_dir, uid);
            snprintf(login_file, sizeof(login_file), "%s/%s_login.txt", user_dir, uid);
            snprintf(reserved_dir, sizeof(reserved_dir), "%s/RESERVED", user_dir);

            // Verify if user exists
            if (!exists(user_dir) || !exists(pass_file)) {
                snprintf(response, sizeof(response), "RMR ERR\n");
            } 
            else {
                // Verify password and login
                int pass_ok = check_password(pass, pass_file);

                if (pass_ok == 2) { // Wrong password
                    snprintf(response, sizeof(response), "RMR WRP\n");
                } else if (!exists(login_file)) { // Not logged in
                    snprintf(response, sizeof(response), "RMR NLG\n");
                } else {
                    // Open RESERVED directory
                    DIR *d = opendir(reserved_dir);
                    struct dirent *dir;
                    int count = 0;
                    
                    #define MAX_RSV 2000
                    rsv_t *list = calloc(MAX_RSV, sizeof(rsv_t));
                    if (!list) {
                        snprintf(response, sizeof(response), "RMR ERR\n");   
                    }

                    // Read all files
                    while (d && (dir = readdir(d)) != NULL) {
                        if (dir->d_name[0] == '.') continue;
                        
                        char r_file[512];
                        snprintf(r_file, sizeof(r_file), "%s/%s", reserved_dir, dir->d_name);

                        FILE *fp = fopen(r_file, "r");
                        if (!fp) continue;

                        char s_uid[10], s_eid[10], s_reserve[10], s_date[15], s_time[15];
                        // Format: UID EID seats date time
                        if (fscanf(fp, "%s %s %s %s %s", s_uid, s_eid, s_reserve, s_date, s_time) == 5) {
                            if (count < MAX_RSV) {
                                strncpy(list[count].eid, s_eid, sizeof(list[count].eid)-1);
                                strncpy(list[count].date, s_date, sizeof(list[count].date)-1);
                                strncpy(list[count].time, s_time, sizeof(list[count].time)-1);
                                strncpy(list[count].reserved, s_reserve, sizeof(list[count].reserved)-1);

                                // Create timestamp for sorting
                                int dday, dmon, dyear, hh, mm, ss;
                                if (sscanf(s_date, "%d-%d-%d", &dday, &dmon, &dyear) == 3 && 
                                    sscanf(s_time, "%d:%d:%d", &hh, &mm, &ss) == 3) {
                                    struct tm tmv = {0};
                                    tmv.tm_mday = dday;
                                    tmv.tm_mon = dmon - 1;
                                    tmv.tm_year = dyear - 1900;
                                    tmv.tm_hour = hh; tmv.tm_min = mm; tmv.tm_sec = ss;
                                    list[count].ts = mktime(&tmv);
                                }
                                count++;
                            }

                        }
                        fclose(fp);
                    }
                    if (d) closedir(d);

                    // Prepare only response
                    if (count == 0) {
                        snprintf(response, sizeof(response), "RMR NOK\n");
                    } else {
                        // Sort (more recents first)
                        qsort(list, (count < MAX_RSV ? count : MAX_RSV), sizeof(rsv_t), rsv_cmp);

                        // Build string in big_buffer
                        char big_buffer[CHUNK_SIZE];
                        int offset = snprintf(big_buffer, sizeof(big_buffer), "RMR OK");

                        // Only send 50 more recent
                        int to_send = (count > 50) ? 50 : count;

                        for (int i = 0; i < to_send; i++) {
                            char item[128];

                            int written = snprintf(item, sizeof(item), " %s %s %s %s", 
                                                list[i].eid, list[i].date, list[i].time, list[i].reserved);

                            // Verify if it still fits in the buffer before cat
                            if (offset + written + 2 < CHUNK_SIZE) {
                                strcat(big_buffer, item);
                                offset += written;
                            } else {
                                break;
                            }
                        }
                        strcat(big_buffer, "\n");
                        
                        // SEND ONLY ONE PACKET
                        sendto(udp_fd, big_buffer, strlen(big_buffer), 0, (struct sockaddr *)client_addr, addrlen);
                        
                        // Clean original response to avoid double code
                        response[0] = '\0';
                    }
                    free(list);
                }
            }
            if (strlen(response) > 0) {
                sendto(udp_fd, response, strlen(response), 0, (struct sockaddr *)client_addr, addrlen);
                response[0] = '\0';
            }
        }
    }

    // Unknown command
    else {
        snprintf(response, sizeof(response), "ERR\n");
    }

    // Send response 
    if (verbose) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr->sin_addr, ip, sizeof ip);
        printf("Client IP: %s\nClient Port: %d\nRequest: %s\nUID: %s\n\n", ip, ntohs(client_addr->sin_port), cmd, uid);
    }
    
    if(strcmp(cmd, "LMR") != 0)
        sendto(udp_fd, response, strlen(response), 0, (struct sockaddr *)client_addr, addrlen);
}
