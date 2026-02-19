#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

int is_int(const char *s);
int isAlnum(const char *s);

int isLeap(int y);
int isValidDate(int d, int m, int y);
int isValidTime(int h, int min);
int isPastDateTime(const char *dateStr, const char *timeStr);
int isValidDateTime(const char *dateStr, const char *timeStr);
int isValidFname(const char *fname);
int isValidEid(const char *eid);
int isfutureTime(const char *dateStr, const char *timeStr);

int recv_all(int sock, char *buffer, int size);
int recv_until_delim(int sock, char *buffer, char delim, int max_size);
ssize_t write_all(int fd, const void *buf, size_t len);
ssize_t read_line(int fd, char *buf, size_t max);

long get_file_size(FILE *fp);
unsigned char *get_file_data(FILE *fp, long size);
int exists(char *path);
int check_password(char *pass, char *pass_file);
int check_input(char *uid, char *pass);

int initialize_last_eid_file();
int get_last_eid(int *eid);
int set_last_eid(int eid);
int get_current_date_time(char *dateStr, char *timeStr);
int get_current_date_time_second(char *dateStr, char *timeStr);
int compare_by_date(const struct dirent **a, const struct dirent **b);

void debug_string(char *label, char *s, int len);