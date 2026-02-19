#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>

#include "tcp_server.h"
#include "client.h"
#include "constants.h"
#include "auxiliary.h"

void handle_tcp_message(int verbose, int tcp_fd, char *cmd, struct sockaddr_in *client_addr) {
    int status = 0;

    // "Uid: %s, Request: %s, Client IP: %s Client Port: %d\n"
    char client_ip[INET_ADDRSTRLEN] = "";
    int client_port = 0;
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof client_ip);
    client_port = ntohs(client_addr->sin_port);

    if (strcmp(cmd, "CRE") == 0) {

        if (verbose) printf("Client IP: %s\nClient Port: %d\nRequest: %s\n", client_ip, client_port, cmd);

        status = handle_event_creation(verbose, tcp_fd);

        // status == 0 handled inside handle_event_creation
        if (status == -1 || status == -2) {
            send(tcp_fd, RCE_ERR, strlen(RCE_ERR), 0);
        }
        else if (status == -3) {
            send(tcp_fd, RCE_WRP, strlen(RCE_WRP), 0);
        }
        else if (status == -4) {
            send(tcp_fd, RCE_NLG, strlen(RCE_NLG), 0);
        }
        else if (status == -5) {
            send(tcp_fd, RCE_NOK, strlen(RCE_NOK), 0);
        }

        close(tcp_fd);
        return;

    } else if (strcmp(cmd, "CLS") == 0) {

        if (verbose) printf("Client IP: %s\nClient Port: %d\nRequest: %s\n", client_ip, client_port, cmd);

        status = handle_event_closure(verbose, tcp_fd);

        if (status ==  0) {
            send(tcp_fd, RCL_OK, strlen(RCL_OK), 0);
        }
        else if (status == -1 || status == -2) {
            send(tcp_fd, RCL_ERR, strlen(RCL_ERR), 0);
        }
        else if (status == -3) {
            send(tcp_fd, RCL_NOK, strlen(RCL_NOK), 0);
        }
        else if (status == -4) {
            send(tcp_fd, RCL_NLG, strlen(RCL_NLG), 0);
        }
        else if (status == -5) {
            send(tcp_fd, RCL_NOE, strlen(RCL_NOE), 0);
        }
        else if (status == -6) {
            send(tcp_fd, RCL_EOW, strlen(RCL_EOW), 0);
        }
        else if (status == -7) {
            send(tcp_fd, RCL_CLO, strlen(RCL_CLO), 0);
        }
        else if (status == -8) {
            send(tcp_fd, RCL_PST, strlen(RCL_PST), 0);
        }
        else if (status == -9) {
            send(tcp_fd, RCL_SLD, strlen(RCL_SLD), 0);
        }

        close(tcp_fd);
        return;

    } else if (strcmp(cmd, "LST") == 0) {

        if (verbose) printf("Client IP: %s\nClient Port: %d\nRequest: %s\n\n", client_ip, client_port, cmd);

        status = handle_events_listing(tcp_fd);

        if (status == -2) {
            send(tcp_fd, RLS_NOK, strlen(RLS_NOK), 0);
        } 
        else if (status == -1) {
            send(tcp_fd, RLS_ERR, strlen(RLS_ERR), 0);
        }

        close(tcp_fd);
        return;

    } else if (strcmp(cmd, "SED") == 0) {

        if (verbose) printf("Client IP: %s\nClient Port: %d\nRequest: %s\n\n", client_ip, client_port, cmd);

        status = handle_event_show(tcp_fd);

        if (status != 0) {
            send(tcp_fd, RSE_NOK, strlen(RSE_NOK), 0);
        }
        // status == 0 handled inside handle_event_show

        close(tcp_fd);
        return;

    } else if (strcmp(cmd, "RID") == 0) {

        if (verbose) printf("Client IP: %s\nClient Port: %d\nRequest: %s\n", client_ip, client_port, cmd);

        status = handle_event_reservation(verbose, tcp_fd);

        if (status ==  0) {
            send(tcp_fd, RRI_ACC, strlen(RRI_ACC), 0);
        }
        else if (status == -1 || status == -2) {
            send(tcp_fd, RRI_ERR, strlen(RRI_ERR), 0);
        }
        else if (status == -3) {
            send(tcp_fd, RRI_WRP, strlen(RRI_WRP), 0);
        }
        else if (status == -4) {
            send(tcp_fd, RRI_NLG, strlen(RRI_NLG), 0);
        }
        else if (status == -5) {
            send(tcp_fd, RRI_NOK, strlen(RRI_NOK), 0);
        }
        else if (status == -6) {
            send(tcp_fd, RRI_CLS, strlen(RRI_CLS), 0);
        }
        else if (status == -7) {
            send(tcp_fd, RRI_PST, strlen(RRI_PST), 0);
        }
        else if (status == -8) {
            send(tcp_fd, RRI_SLD, strlen(RRI_SLD), 0);
        }
        // status == -9 handled inside handle_event_reservation

        close(tcp_fd);
        return;

    } else if (strcmp(cmd, "CPS") == 0) {

        if (verbose) printf("Client IP: %s\nClient Port: %d\nRequest: %s\n", client_ip, client_port, cmd);

        status = handle_change_password(verbose, tcp_fd);

        // status == 0 handled inside handle_change_password
        if (status == -1 || status == -2) {
            send(tcp_fd, RCP_ERR, strlen(RCP_ERR), 0);
        }
        else if (status == -3) {
            send(tcp_fd, RCP_WRP, strlen(RCP_WRP), 0);
        }
        else if (status == -4) {
            send(tcp_fd, RCP_NLG, strlen(RCP_NLG), 0);
        }
        else if (status == -5) {
            send(tcp_fd, RCP_NID, strlen(RCP_NID), 0);
        }
        
        close(tcp_fd);
        return;

    } else {
        // Invalid command
        if (verbose) {
            printf("Invalid TCP command received from:\n");
            printf("Client IP: %s\n", client_ip);
            printf("Client Port: %d\n\n", client_port);
        }

        send(tcp_fd, ERR_MSG, strlen(ERR_MSG), 0);
        close(tcp_fd);
        return;
    }
}

/* CRE UID (6) password (8) name (1-10) event_date (10+1+5=16) attendance_size (2-3) Fname (5-24) Fsize (1-8) Fdata
 -1: Error handling command
 -2: Syntax incorrect or invalid values
 -3: Wrong password
 -4: User not logged in
 -5: Max number of events reached
  0: Success */
int handle_event_creation(int verbose, int tcp_fd) {
    int n;
    char fdata_buffer[CHUNK_SIZE];
    FILE *fp;

    char UID[7];
    char password[9];
    char name[11];
    char date[11];
    char hour[6];
    char attendance_size_str[4];
    char Fname[25];
    char Fsize_str[9];

    // UID (6)
    n = recv_all(tcp_fd, UID, 7);
    if (n == -1) return -1;
    if (UID[6] != ' ') return -2;
    UID[6] = '\0';
    if (!is_int(UID)) return -2;

    if (verbose) printf("UID: %s\n\n", UID);

    // password (8)
    n = recv_all(tcp_fd, password, 9);
    if (n == -1) return -1;
    if (password[8] != ' ') return -2;
    password[8] = '\0';
    if (!isAlnum(password)) return -2;

    // name (1-10)
    n = recv_until_delim(tcp_fd, name, ' ', 11);
    if (n == -1) return -1;
    if (name[n - 1] != ' ') return -2;
    name[n - 1] = '\0';
    if (!isAlnum(name)) return -2;

    // event_date (10+1+5=16)
    n = recv_all(tcp_fd, date, 11);
    if (n == -1) return -1;
    if (date[10] != ' ') return -2;
    date[10] = '\0';
    n = recv_all(tcp_fd, hour, 6);
    if (n == -1) return -1;
    if (hour[5] != ' ') {
        return -2;
    }
    hour[5] = '\0';
    if (!isValidDateTime(date, hour)) return -2;

    // attendance_size (2-3)
    n = recv_until_delim(tcp_fd, attendance_size_str, ' ', 4);
    if (n == -1) return -1; // Error in recv
    if (attendance_size_str[n - 1] != ' ') return -2;
    attendance_size_str[n - 1] = '\0';
    if (!is_int(attendance_size_str)) return -2;

    // Fname (5-24)
    n = recv_until_delim(tcp_fd, Fname, ' ', 25);
    if (n == -1) return -1; // Error in recv
    if (Fname[n - 1] != ' ') return -2;
    Fname[n - 1] = '\0';
    if (!isValidFname(Fname)) return -2;

    // Fsize (1-8)
    n = recv_until_delim(tcp_fd, Fsize_str, ' ', 9);
    if (n == -1) return -1; // Error in recv
    if (Fsize_str[n - 1] != ' ') return -2;
    Fsize_str[n - 1] = '\0';
    if (!is_int(Fsize_str)) return -2;
    long Fsize = atol(Fsize_str);
    if (Fsize > MAX_FILE_SIZE) return -2;

    // Verify if user exists, password matches and is logged in
    char user_path[SIZE_ID_PATH]; // ESDIR/USERS/uid
    snprintf(user_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_USERS, UID);
    if (!exists(user_path)) return -2; // User not registered
    char pass_file[SIZE_FRST_PATH]; // ESDIR/USERS/uid/uid_pass.txt
    snprintf(pass_file, SIZE_FRST_PATH, "%s/%s_pass.txt", user_path, UID);
    if (!exists(pass_file)) return -2;
    int pass_check = check_password(password, pass_file);
    if (pass_check == 0) return -1; // Error opening pass_file
    else if (pass_check == 2) return -3; // Wrong password
    char login_file[SIZE_FRST_PATH]; // ESDIR/USERS/uid/uid_login.txt
    snprintf(login_file, SIZE_FRST_PATH, "%s/%s_login.txt", user_path, UID);
    if (!exists(login_file)) return -4;

    // Verify event_eid
    int event_eid;
    if (get_last_eid(&event_eid) == -1) return -1;
    event_eid++;
    if (event_eid > 999) return -5; // Max number of events reached

    // --------- Create event folders and files ---------

    // Create event directory
    char event_dir[4];
    snprintf(event_dir, 4, "%03d", event_eid);
    char event_path[SIZE_ID_PATH]; // ESDIR/EVENTS/eid
    snprintf(event_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_EVENTS, event_dir);
    if (mkdir(event_path, 0777) == -1) return -1;

    // Description
    char desc_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/DESCRIPTION
    snprintf(desc_path, SIZE_FRST_PATH, "%s/DESCRIPTION", event_path);
    if (mkdir(desc_path, 0777) == -1) {
        rmdir(event_path);
        return -1;
    }

    // Fdata
    char fdata_path[SIZE_SCND_PATH]; // ESDIR/EVENTS/eid/DESCRIPTION/Fname
    snprintf(fdata_path, SIZE_SCND_PATH, "%s/%s", desc_path, Fname);
    fp = fopen(fdata_path, "wb");
    if (!fp) {
        rmdir(desc_path);
        rmdir(event_path);
        return -1;
    }
    long remaining = Fsize;
    while (remaining > 0) {
        size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        n = recv_all(tcp_fd, fdata_buffer, to_read);
        if (n == -1) {
            fclose(fp);
            remove(fdata_path);
            rmdir(desc_path);
            rmdir(event_path);
            return -1;
        }
        fwrite(fdata_buffer, 1, n, fp);
        remaining -= n;
    }
    fclose(fp);

    /* char end_char;
    n = recv_all(tcp_fd, &end_char, 1);
    if (n != 1 || end_char != '\n') {
        fclose(fp);
        remove(fdata_path);
        rmdir(desc_path);
        rmdir(event_path);
    } */

    // START_eid.txt
    char start_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/START_eid.txt
    snprintf(start_path, SIZE_FRST_PATH, "%s/START_%s.txt", event_path, event_dir);
    fp = fopen(start_path, "w");
    if (!fp) {
        remove(fdata_path);
        rmdir(desc_path);
        rmdir(event_path);
        return -1;
    }
    // UID event_name desc_fname event_attend start_date start_time
    fprintf(fp, "%s %s %s %s %s %s\n", UID, name, Fname, attendance_size_str, date, hour);
    fclose(fp);

    // RES_eid.txt
    char res_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/RES_eid.txt
    snprintf(res_path, SIZE_FRST_PATH, "%s/RES_%s.txt", event_path, event_dir);
    fp = fopen(res_path, "w");
    if (!fp) {
        remove(fdata_path);
        rmdir(desc_path);
        remove(start_path);
        rmdir(event_path);
        return -1;
    }
    fprintf(fp, "0\n");
    fclose(fp);

    // RESERVATIONS
    char reservations_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/RESERVATIONS
    snprintf(reservations_path, SIZE_FRST_PATH, "%s/RESERVATIONS", event_path);
    if (mkdir(reservations_path, 0777) == -1) {
        remove(fdata_path);
        rmdir(desc_path);
        remove(start_path);
        remove(res_path);
        rmdir(event_path);
        return -1;
    }

    // Update client's CREATED
    char created_path[SIZE_SCND_PATH]; // ESDIR/USERS/uid/CREATED/eid.txt
    snprintf(created_path, SIZE_SCND_PATH, "%s/CREATED/%s.txt", user_path, event_dir);
    fp = fopen(created_path, "w");
    if (!fp) {
        remove(fdata_path);
        rmdir(desc_path);
        remove(start_path);
        remove(res_path);
        rmdir(reservations_path);
        rmdir(event_path);
        return -1;
    }
    // EID event_name desc_fname event_attend start_date start_time
    fprintf(fp, "%s %s %s %s %s %s\n", event_dir, name, Fname, attendance_size_str, date, hour);
    fclose(fp);

    // Update last_eid.txt if everything went well
    if (set_last_eid(event_eid) == -1) {
        remove(fdata_path);
        rmdir(desc_path);
        remove(start_path);
        remove(res_path);
        rmdir(reservations_path);
        rmdir(event_path);
        remove(created_path);
        return -1;
    }

    char ok_msg[MAXBUF];
    snprintf(ok_msg, MAXBUF,"%s %s\n", RCE_OK, event_dir);
    
    send(tcp_fd, ok_msg, strlen(ok_msg), 0);
    return 0;
}

/* CLS UID (6) password (8) EID (3)
 -1: Error handling command
 -2: Syntax incorrect or invalid values
 -3: User doesn't exist, wrong password
 -4: User not logged in
 -5: Event doesn't exist
 -6: Event not created by User UID
 -7: Event previously closed by user
 -8: Event in the past
 -9: Event created by user sold out
  0: Success */
int handle_event_closure(int verbose, int tcp_fd) {
    int n;
    FILE *fp;

    char UID[7];
    char password[9];
    char EID[4];

    // UID (6)
    n = recv_all(tcp_fd, UID, 7);
    if (n == -1) return -1;
    if (UID[6] != ' ') return -2;
    UID[6] = '\0';
    if (!is_int(UID)) return -2;

    if (verbose) printf("UID: %s\n\n", UID);

    // password (8)
    n = recv_all(tcp_fd, password, 9);
    if (n == -1) return -1;
    if (password[8] != ' ') return -2;
    password[8] = '\0';
    if (!isAlnum(password)) return -2;

    // EID (3)
    n = recv_all(tcp_fd, EID, 4);
    if (n == -1) return -1;
    if (EID[3] != '\n') return -2;
    EID[3] = '\0';
    if (!isValidEid(EID)) return -2;

    // Verify if user exists, password matches and is logged in
    char user_path[SIZE_ID_PATH]; // ESDIR/USERS/uid
    snprintf(user_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_USERS, UID);
    if (!exists(user_path)) return -3; // User not registered
    char pass_file[SIZE_FRST_PATH];
    snprintf(pass_file, SIZE_FRST_PATH, "%s/%s_pass.txt", user_path, UID);
    if (!exists(pass_file)) return -3; // User not registered
    int pass_check = check_password(password, pass_file);
    if (pass_check == 0) return -1; // Error opening pass_file
    else if (pass_check == 2) return -3; // Wrong password
    char login_file[SIZE_FRST_PATH];
    snprintf(login_file, SIZE_FRST_PATH, "%s/%s_login.txt", user_path, UID);
    if (!exists(login_file)) return -4; // User not logged in

    // Verify if event EID exists
    int last_eid;
    if (get_last_eid(&last_eid) == -1) return -1;
    int int_eid = atoi(EID);

    char event_path[SIZE_ID_PATH]; // ESDIR/EVENTS/eid
    snprintf(event_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_EVENTS, EID);
    if (!exists(event_path) || int_eid > last_eid) return -5; // Event doesn't exist

    // Get event details
    char start_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/START_eid.txt
    snprintf(start_path, SIZE_FRST_PATH, "%s/START_%s.txt", event_path, EID);
    // START file format: UID name desc_fname attendance date time
    fp = fopen(start_path, "r");
    if (!fp) return -1;
    char creator_uid[7];
    char event_attend[4];
    char start_date[11];
    char start_time[6];
    if (fscanf(fp, "%6s %*s %*s %3s %10s %5s", creator_uid, event_attend, start_date, start_time) != 4) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (strcmp(creator_uid, UID) != 0) return -6; // Event not created by User UID

    char end_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/END_eid.txt
    snprintf(end_path, SIZE_FRST_PATH, "%s/END_%s.txt", event_path, EID);
    if (exists(end_path)) return -7; // Event previously closed by user

    if(isPastDateTime(start_date, start_time)) return -8; // Event in the past

    // Check reservations
    char res_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/RES_eid.txt
    snprintf(res_path, SIZE_FRST_PATH, "%s/RES_%s.txt", event_path, EID);
    fp = fopen(res_path, "r");
    if (!fp) return -1;
    int reserved_count;
    if (fscanf(fp, "%d", &reserved_count) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (reserved_count == atoi(event_attend)) return -9; // Event created by user sold out

    // Close the event
    fp = fopen(end_path, "w");
    if (!fp) return -1;
    // Get current date and time
    char current_date[11];
    char current_time[6];
    if (get_current_date_time(current_date, current_time) == -1) {
        fclose(fp);
        return -1;
    }
    fprintf(fp, "%s %s\n", current_date, current_time);
    fclose(fp);

    return 0;
}

/* LST
 -1: Error handling command
 -2: No events
  0: Sucess */
int handle_events_listing(int tcp_fd) {
    DIR *d;
    struct dirent *dir;
    char events_path[SIZE_ID_PATH];
    snprintf(events_path, SIZE_ID_PATH, "%s/%s", DIR_ES, DIR_EVENTS);

    // Open the events directory
    d = opendir(events_path);
    if (!d) return -1;

    int eids[MAX_EID + 1];
    int ecnt = 0;

    // 1. Collect EIDs (directories) and store them in an array
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
        int eid_i = atoi(dir->d_name);
        // Only collect valid positive EIDs within limits
        if (eid_i > 0 && ecnt < (MAX_EID + 1)) eids[ecnt++] = eid_i;
    }
    closedir(d);

    // If no events are found, send the negative response
    if (ecnt == 0) {
        return -2;
    }

    // Sort EIDs
    for (int i = 1; i < ecnt; i++) {
        int key = eids[i];
        int j = i - 1;
        while (j >= 0 && eids[j] > key) {
            eids[j + 1] = eids[j];
            j--;
        }
        eids[j + 1] = key;
    }

    //  Send the initial protocol header (without newline yet)
    if (write_all(tcp_fd, "RLS OK", 6) < 0) return -1;

    // Process and send each event individually to save memory
    for (int idx = 0; idx < ecnt; idx++) {
        char eid_str[8];
        snprintf(eid_str, sizeof(eid_str), "%03d", eids[idx]);

        char event_dir[SIZE_ID_PATH];
        char start_file[SIZE_FRST_PATH], res_file[SIZE_FRST_PATH], end_file[SIZE_FRST_PATH];

        // Build paths for the event's metadata files
        snprintf(event_dir, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_EVENTS, eid_str);
        snprintf(start_file, SIZE_FRST_PATH, "%s/START_%s.txt", event_dir, eid_str);
        snprintf(res_file, SIZE_FRST_PATH, "%s/RES_%s.txt", event_dir, eid_str);
        snprintf(end_file, SIZE_FRST_PATH, "%s/END_%s.txt", event_dir, eid_str);

        // Default values for an event
        char state_s[4];
        char name[12];
        char date[16];
        char time_s[8];

        // Logic to determine event state (0: Past, 1: Active, 2: Sold Out, 3: Closed)
        FILE *fp = fopen(start_file, "r");
        if (fp) {
            char uid[7], fname[30], attend[4];
            if (fscanf(fp, "%6s %10s %24s %3s %10s %5s", uid, name, fname, attend, date, time_s) == 6) {

                if (exists(end_file)) {
                    strcpy(state_s, "3");
                } else if (!isfutureTime(date, time_s)) {
                    strcpy(state_s, "0");
                } else {
                    FILE *fr = fopen(res_file, "r");
                    if (fr) {
                        int reserved = 0;
                        fscanf(fr, "%d", &reserved);
                        fclose(fr);
                        int attend_int = atoi(attend);
                        if (attend_int <= reserved) strcpy(state_s, "2");
                        else strcpy(state_s, "1");
                    }
                }
            }
            fclose(fp);
        }

        // Format the event as a set of tokens separated by spaces
        char item[MAXBUF];
        int len = snprintf(item, sizeof(item), " %s %s %s %s %s", 
                           eid_str, name, state_s, date, time_s);

        // Send this event's chunk immediately. If write_all fails, connection is lost.
        if (write_all(tcp_fd, item, len) < 0) {
            return -1;
        }
    }

    // 4. Send the final newline to complete the message according to protocol
    if (write_all(tcp_fd, "\n", 1) < 0) return -1;

    return 0;
}

/* SED EID (3)
 -1: Error handling command
 -2: Syntax incorrect or invalid values
 -3: Event doesn't exist, there is no file to be sent
  0: Sucess */
int handle_event_show(int tcp_fd) {
    int n;
    FILE *fp;
    
    char EID[4];

    // EID (3)
    n = recv_all(tcp_fd, EID, 4);
    if (n == -1) return -1;
    if (EID[3] != '\n') return -2;
    EID[3] = '\0';
    if (!isValidEid(EID)) return -2;
    
    // Verify if event EID exists
    int last_eid;
    if (get_last_eid(&last_eid) == -1) return -1;
    int int_eid = atoi(EID);

    char event_path[SIZE_ID_PATH]; // ESDIR/EVENTS/eid
    snprintf(event_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_EVENTS, EID);
    if (!exists(event_path) || int_eid > last_eid) return -3; // Event doesn't exist

    // Get event details
    char start_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/START_eid.txt
    snprintf(start_path, SIZE_FRST_PATH, "%s/START_%s.txt", event_path, EID);
    // START file format: UID name desc_fname attendance date time
    fp = fopen(start_path, "r");
    if (!fp) return -1;
    char creator_uid[7];
    char event_name[11];
    char Fname[25];
    char event_attend[4];
    char start_date[11];
    char start_time[6];
    if (fscanf(fp, "%6s %10s %24s %3s %10s %5s", creator_uid, event_name, Fname, event_attend, start_date, start_time) != 6) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    
    // Check reservations
    char res_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/RES_eid.txt
    snprintf(res_path, SIZE_FRST_PATH, "%s/RES_%s.txt", event_path, EID);
    fp = fopen(res_path, "r");
    if (!fp) return -1;
    char reserved_count[4];
    if (fscanf(fp, "%s", reserved_count) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Get Fdata if it exists
    char fdata_path[SIZE_SCND_PATH]; // ESDIR/EVENTS/eid/DESCRIPTION/Fname
    snprintf(fdata_path, SIZE_SCND_PATH, "%s/DESCRIPTION/%s", event_path, Fname);

    long Fsize = 0;
    unsigned char *fdata = NULL;
    if (exists(fdata_path)) {
        FILE *df = fopen(fdata_path, "rb");
        if (df) {
            Fsize = get_file_size(df);
            if (Fsize > 0) {
                fdata = get_file_data(df, Fsize);
            }
            fclose(df);
            if (!fdata && Fsize > 0) return -1; // Could not read data
        } else {
            return -1; // File not openable
        }
    } else return -3; // There is no Fname

    if (Fsize > MAX_FILE_SIZE) return -2; // Invalid fsize

    // Prepare message header:
    // RSE OK UID event_name date time attendance_size seats_reserved Fname Fsize
    char header[MAXBUF];
    // char Fsize_str[9];
    // snprintf(Fsize_str, 9, "%ld", Fsize);

    snprintf(header, sizeof(header), "%s %s %s %s %s %s %s %s %ld ", RSE_OK,
            creator_uid, event_name, start_date, start_time, event_attend, reserved_count, Fname, Fsize);
    
    // Send header
    if (write_all(tcp_fd, header, strlen(header)) < 0) {
        if (fdata) free(fdata);
        return -1;
    }

    // Send fdata
    if (write_all(tcp_fd, fdata, Fsize) < 0) {
        if (fdata) free(fdata);
        return -1;
    }
    if (fdata) free(fdata);

    // Final newline to terminate protocol message
    if (write_all(tcp_fd, "\n", 1) < 0) return -1;

    return 0;
}

/* RID UID (6) password (8) EID (3) people (1-3)
 -1: Error handling command
 -2: Syntax incorrect or invalid values
 -3: Wrong password
 -4: User not logged in
 -5: Event not active (doesn't exist)
 -6: Event closed
 -7: Event in the past
 -8: Event sold out
 -9: Reservations rejected (not enough places)
 0: Success */
int handle_event_reservation(int verbose, int tcp_fd) {
    int n;
    FILE *fp;

    char UID[7];
    char password[9];
    char EID[4];
    char people_str[4];
    int people_int;

    // UID (6)
    n = recv_all(tcp_fd, UID, 7);
    if (n == -1) return -1;
    if (UID[6] != ' ') return -2;
    UID[6] = '\0';
    if (!is_int(UID)) return -2;

    if (verbose) printf("UID: %s\n\n", UID);

    // password (8)
    n = recv_all(tcp_fd, password, 9);
    if (n == -1) return -1;
    if (password[8] != ' ') return -2;
    password[8] = '\0';
    if (!isAlnum(password)) return -2;

    // EID (3)
    n = recv_all(tcp_fd, EID, 4);
    if (n == -1) return -1;
    if (EID[3] != ' ') return -2;
    EID[3] = '\0';
    if (!isValidEid(EID)) return -2;

    // people (1-3)
    n = recv_until_delim(tcp_fd, people_str, '\n', 4);
    if (n == -1) return -1; // Error in recv
    if (people_str[n - 1] != '\n') return -2;
    people_str[n - 1] = '\0';
    if (!is_int(people_str)) return -2;
    people_int = atoi(people_str);

    // Verify if user exists, password matches and is logged in
    char user_path[SIZE_ID_PATH]; // ESDIR/USERS/uid
    snprintf(user_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_USERS, UID);
    if (!exists(user_path)) return -2; // User not registered
    char pass_file[SIZE_FRST_PATH];
    snprintf(pass_file, SIZE_FRST_PATH, "%s/%s_pass.txt", user_path, UID);
    if (!exists(pass_file)) return -2; // User not registered
    int pass_check = check_password(password, pass_file);
    if (pass_check == 0) return -1; // Error opening pass_file
    else if (pass_check == 2) return -3; // Wrong password
    char login_file[SIZE_FRST_PATH];
    snprintf(login_file, SIZE_FRST_PATH, "%s/%s_login.txt", user_path, UID);
    if (!exists(login_file)) return -4; // User not logged in

    // Verify if event EID exists
    int last_eid;
    if (get_last_eid(&last_eid) == -1) return -1;
    int int_eid = atoi(EID);

    char event_path[SIZE_ID_PATH]; // ESDIR/EVENTS/eid
    snprintf(event_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_EVENTS, EID);
    if (!exists(event_path) || int_eid > last_eid) return -5; // Event not active (doesn't exist)

    // Get event details
    char start_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/START_eid.txt
    snprintf(start_path, SIZE_FRST_PATH, "%s/START_%s.txt", event_path, EID);
    // START file format: UID name desc_fname attendance date time
    fp = fopen(start_path, "r");
    if (!fp) return -1;
    char event_attend[4];
    char start_date[11];
    char start_time[6];
    if (fscanf(fp, "%*s %*s %*s %3s %10s %5s", event_attend, start_date, start_time) != 3) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Verify event closure
    char end_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/END_eid.txt
    snprintf(end_path, SIZE_FRST_PATH, "%s/END_%s.txt", event_path, EID);
    if (exists(end_path)) return -6; // Event closed

    // Verify if event is in the past
    if(isPastDateTime(start_date, start_time)) return -7; // Event in the past

    // Check reservations
    char res_path[SIZE_FRST_PATH]; // ESDIR/EVENTS/eid/RES_eid.txt
    snprintf(res_path, SIZE_FRST_PATH, "%s/RES_%s.txt", event_path, EID);
    fp = fopen(res_path, "r");
    if (!fp) return -1;
    int reserved_count;
    if (fscanf(fp, "%d", &reserved_count) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    int event_attend_int = atoi(event_attend);
    if (reserved_count == event_attend_int) return -8; // Event created by user sold out

    // Check if enough seats are available
    int remaining_places = event_attend_int - reserved_count;
    if (people_int > remaining_places) {
        char rej_msg[MAXBUF];
        snprintf(rej_msg, MAXBUF,"%s %d\n", RRI_REJ, remaining_places);
        send(tcp_fd, rej_msg, strlen(rej_msg), 0);
        return -9;
    }

    // --------------- Create reservation files ---------------

    // Get current date and time
    char current_date[11];
    char current_time[9];
    if (get_current_date_time_second(current_date, current_time) == -1) return -1;

    // Files' paths
    char res_file_name[SIZE_FILE_NAME];
    snprintf(res_file_name, SIZE_FILE_NAME, "R-%s-%s_%s.txt", UID, current_date, current_time);
    char reservations_path[SIZE_SCND_PATH];
    snprintf(reservations_path, SIZE_SCND_PATH, "%s/RESERVATIONS/%s", event_path, res_file_name);
    char reserved_path[SIZE_SCND_PATH];
    snprintf(reserved_path, SIZE_SCND_PATH, "%s/RESERVED/%s", user_path, res_file_name);
    
    fp = fopen(reservations_path, "w");
    if (!fp) return -1;
    fprintf(fp, "%s %s %s %s %s\n", UID, EID, people_str, current_date, current_time);
    fclose(fp);

    fp = fopen(reserved_path, "w");
    if (!fp) {
        remove(reservations_path);
        return -1;
    }
    fprintf(fp, "%s %s %s %s %s\n", UID, EID, people_str, current_date, current_time);
    fclose(fp);

    // Update RES_eid.txt
    reserved_count += people_int;
    fp = fopen(res_path, "w");
    if (!fp) {
        remove(reservations_path);
        remove(reserved_path);
        return -1;
    }
    fprintf(fp, "%d\n", reserved_count);
    fclose(fp);

    return 0; // Event open, reservation accepted
}


/*  CPS UID(6) oldPassword(8) newPassword(8)
 -1: Error handling command
 -2: Syntax incorrect or invalid values
 -3: Wrong password
 -4: User not logged in
 -5: User does not exist
  0: Success */
int handle_change_password(int verbose, int tcp_fd) {
    int n;

    char UID[7];
    char oldpass[9];
    char newpass[9];

    // UID (6)
    n = recv_all(tcp_fd, UID, 7);
    if (n == -1) return -1;
    if (UID[6] != ' ') return -2;
    UID[6] = '\0';
    if (!is_int(UID)) return -2;

    if (verbose) printf("UID: %s\n\n", UID);

    // oldPassword (8)
    n = recv_all(tcp_fd, oldpass, 9);
    if (n == -1) return -1;
    if (oldpass[8] != ' ') return -2;
    oldpass[8] = '\0';
    if (!isAlnum(oldpass)) return -2;

    // newPassword (8) terminated by '\n'
    n = recv_until_delim(tcp_fd, newpass, '\n', 9);
    if (n == -1) return -1;
    if (newpass[n - 1] != '\n') return -2;
    newpass[n - 1] = '\0';
    if (strlen(newpass) != 8 || !isAlnum(newpass)) return -2;

    // Verify if user exists, password matches and is logged in
    char user_path[SIZE_ID_PATH]; // ESDIR/USERS/uid
    snprintf(user_path, SIZE_ID_PATH, "%s/%s/%s", DIR_ES, DIR_USERS, UID);
    if (!exists(user_path)) return -5; // User does not exist
    char pass_file[SIZE_FRST_PATH]; // ESDIR/USERS/uid/uid_pass.txt
    snprintf(pass_file, SIZE_FRST_PATH, "%s/%s_pass.txt", user_path, UID);
    if (!exists(pass_file)) return -5; // User not registered
    int pass_check = check_password(oldpass, pass_file);
    if (pass_check == 0) return -1; // Error opening pass_file
    if (pass_check == 2) return -3; // Wrong password
    char login_file[SIZE_FRST_PATH]; // ESDIR/USERS/uid/uid_login.txt
    snprintf(login_file, SIZE_FRST_PATH, "%s/%s_login.txt", user_path, UID);
    if (!exists(login_file)) return -4; // User not logged in

    FILE *fp = fopen(pass_file, "w");
    if (!fp) return -1;
    fprintf(fp, "%s", newpass);
    fclose(fp);

    /* Send response (RCP_OK already contains terminating '\n') */
    send(tcp_fd, RCP_OK, strlen(RCP_OK), 0);
    return 0;
}
