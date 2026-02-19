// Auxiliary functions

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>  
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h> 
#include <unistd.h>


#include "auxiliary.h"
#include "constants.h"


int is_int(const char *s) {
    
    for (int i = 0; s[i] != '\0'; i++) {
        if (!isdigit((unsigned char)s[i])) {
            return 0; 
        }
    }
    return 1; 
}

int isValidEid(const char *eid) {
    if (is_int(eid)) {
        int eid_num = atoi(eid);
        if (eid_num > 0 && eid_num <= 999) {
            return 1;
        }
    }
    return 0;
}

int recv_until_delim(int sock, char *buffer, char delim, int max_size) {
    int total = 0;
    int n;
    char c;

    while (total < max_size) {
        n = recv(sock, &c, 1, 0);
        if (n <= 0) {
            return -1; // Error or connection closed
        }

        buffer[total++] = c;

        if (c == delim) {
            break;
        }
    }

    return total;
}

int recv_all(int sock, char *buffer, int size) {
    int total = 0;
    int n;

    while (total < size) {
        n = recv(sock, buffer + total, size - total, 0);
        if (n <= 0) {
            return -1;
        }

        total += n;
    }

    return total;
}

int isAlnum(const char *s) {

    for (int i = 0; s[i] != '\0'; i++) {
        if (!isalnum((unsigned char)s[i])) {
            return 0; // found character non-alphanumeric
        }
    }
    return 1; // only alphanumeric character
}

int isLeap(int y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

int isValidDate(int d, int m, int y) {

    if (y < 1 || m < 1 || m > 12 || d < 1) return 0;

    int daysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (m == 2 && isLeap(y))
        return d <= 29;

    return d <= daysInMonth[m - 1];
}

int isValidTime(int h, int min) {
    return (h >= 0 && h <= 23 && min >= 0 && min <= 59);
}

int isPastDateTime(const char *dateStr, const char *timeStr) {
    int d, m, y, h, min;

    if (sscanf(dateStr, "%d-%d-%d", &d, &m, &y) != 3) return 0;
    if (sscanf(timeStr, "%d:%d", &h, &min) != 2) return 0;

    // validate date and time
    if (!isValidDate(d, m, y) || !isValidTime(h, min)) return 0;

    // get real date and time
    time_t t = time(NULL);
    struct tm *now = localtime(&t);

    struct tm input = {0};
    input.tm_year = y - 1900;
    input.tm_mon  = m - 1;
    input.tm_mday = d;
    input.tm_hour = h;
    input.tm_min  = min;

    time_t inputTime = mktime(&input);
    time_t nowTime   = mktime(now);

    return inputTime < nowTime;  // returns 1 if date is in the past
}

int isValidDateTime(const char *dateStr, const char *timeStr) {
    int d, m, y, h, min;

    if (sscanf(dateStr, "%d-%d-%d", &d, &m, &y) != 3) return 0;
    if (sscanf(timeStr, "%d:%d", &h, &min) != 2) return 0;

    // validate date and time
    if (!isValidDate(d, m, y) || !isValidTime(h, min)) return 0;

    if (isPastDateTime(dateStr, timeStr)) return 0;

    return 1; // valid date time in the future
}

int isfutureTime(const char *dateStr, const char *timeStr) {
    int d, m, y, h, min;

    if (sscanf(dateStr, "%d-%d-%d", &d, &m, &y) != 3) return 0;
    if (sscanf(timeStr, "%d:%d", &h, &min) != 2) return 0;
    // get real date and time
    // returns 1 if date is in the future
    time_t t = time(NULL);
    struct tm *now = localtime(&t);

    struct tm input = {0};
    input.tm_year = y - 1900;
    input.tm_mon  = m - 1;
    input.tm_mday = d;
    input.tm_hour = h;
    input.tm_min  = min;

    time_t inputTime = mktime(&input);
    time_t nowTime   = mktime(now);

    return inputTime > nowTime;
}


ssize_t write_all(int fd, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = buf;

    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n <= 0) return -1;   // error
        total += n;
    }

    return total;
}

ssize_t read_line(int fd, char *buf, size_t max) {
    size_t i = 0;

    while (i < max - 1) {
        ssize_t n = read(fd, &buf[i], 1);
        if (n == 0) break;       // closed connection
        if (n < 0) {
            if (errno == EINTR) continue; // interrupted, try again
            return -1;    // erro
        }
        if (buf[i] == '\n') { i++; break; }
        i++;
    }

    buf[i] = '\0';
    return i;
}

long get_file_size(FILE *fp) {

    if (fseek(fp, 0, SEEK_END) != 0) {  
        return -1;
    }

    long size = ftell(fp); 
    if (size == -1) {
        return -1;
    }
    
    fseek(fp, 0, SEEK_SET);

    return size;
}

unsigned char *get_file_data(FILE *fp, long size) {
    if (!fp || size <= 0) return NULL;

    unsigned char* buffer = malloc(size);
    if (!buffer) return NULL;

    size_t n = fread(buffer, 1, size, fp);

    if (n != (size_t)size) {
        free(buffer);
        return NULL;
    }

    return buffer;  
}

int exists(char *path) {
    struct stat state;
    return stat(path, &state) == 0;
}


int check_password(char *pass, char *pass_file){
    FILE *fp = fopen(pass_file, "r");
    if (fp) {
        char stored_pass[20];
        if (fgets(stored_pass, sizeof(stored_pass), fp)) {
            stored_pass[strcspn(stored_pass, "\n")] = 0; // Remove \n from the file read
        }
        fclose(fp);
        if (strcmp(pass, stored_pass) == 0) return 1;
        else return 2; // Wrong Password
    }  
    return 0; // Error oppening pass_file              
}

int check_input(char *uid, char *pass){

    return (strlen(pass) == 8 && strlen(uid) == 6 && 
    is_int(uid) && isAlnum(pass));
    
}

int isValidFname(const char *fname) {
    int len = strlen(fname);

    if (len < 5) return 0;
    if (fname[len - 4] != '.' ) return 0; // No extension

    for (int i = 0; i < len; i++) {
        if (!isalnum((unsigned char)fname[i]) && fname[i] != '_' && fname[i] != '-' && fname[i] != '.') {
            return 0; // Invalid character found
        }
    }
    return 1;
}

int initialize_last_eid_file() {
    FILE *fp = fopen(LAST_EID_PATH, "wx");
    if (!fp) {
        if (errno == EEXIST) {
            return 0; // Already exists
        }
        return -1; // Error creating file
    }
    fprintf(fp, "000");
    fclose(fp);
    return 1;
}


int get_last_eid(int *eid) {
    FILE *fp = fopen(LAST_EID_PATH, "r");
    if (!fp) return -1;

    if (fscanf(fp, "%3d", eid) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int set_last_eid(int eid) {
    FILE *fp = fopen(LAST_EID_PATH, "w");
    if (!fp) return -1;

    fprintf(fp, "%03d", eid);
    fclose(fp);
    return 0;
}

int get_current_date_time(char *dateStr, char *timeStr) {
    time_t t = time(NULL);
    struct tm *now = localtime(&t);

    if (now == NULL) return -1;

    if (strftime(dateStr, 11, "%d-%m-%Y", now) == 0) return -1;
    if (strftime(timeStr, 6, "%H:%M", now) == 0) return -1;

    return 0;
}

int get_current_date_time_second(char *dateStr, char *timeStr) {
    time_t t = time(NULL);
    struct tm *now = localtime(&t);

    if (now == NULL) return -1;

    if (strftime(dateStr, 11, "%d-%m-%Y", now) == 0) return -1;
    if (strftime(timeStr, 9, "%H:%M:%S", now) == 0) return -1;

    return 0;
}

int compare_by_date(const struct dirent **a, const struct dirent **b) {
    int eid1, d1, m1, a1, h1, min1, s1;
    int eid2, d2, m2, a2, h2, min2, s2;

    // R-eid-dd-mm-aaaa_hh:mm:ss.txt
    sscanf((*a)->d_name, "R-%d-%d-%d-%d_%d:%d:%d", &eid1, &d1, &m1, &a1, &h1, &min1, &s1);
    sscanf((*b)->d_name, "R-%d-%d-%d-%d_%d:%d:%d", &eid2, &d2, &m2, &a2, &h2, &min2, &s2);

    // Compare
    if (a1 != a2) return a2 - a1;
    if (m1 != m2) return m2 - m1;
    if (d1 != d2) return d2 - d1;
    if (h1 != h2) return h2 - h1;
    if (min1 != min2) return min2 - min1;
    return s2 - s1;
}

void debug_string(char *label, char *s, int len) {
    printf("%s: [", label);
    for (int i = 0; i < len; i++) {
        if (s[i] == '\0') {
            printf("\\0");
            break;
        } else if (s[i] == '\n') {
            printf("\\n");
        } else if (s[i] == '\r') {
            printf("\\r");
        } else if (s[i] == ' ') {
            printf("_"); // Space as underscore
        } else {
            printf("%c", s[i]);
        }
    }
    printf("]\n");
}