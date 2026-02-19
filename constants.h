//--------------------------------------------------------------------

#define PORT 58083 // Default port number by omission (group 83)

#define DIR_ES "ESDIR"
#define DIR_USERS "USERS"
#define DIR_EVENTS "EVENTS"
#define LAST_EID_PATH "ESDIR/EVENTS/last_eid.txt"

/* UID/EID path sizes:
ESDIR/USERS/uid
ESDIR/EVENTS/eid
*/
#define SIZE_ID_PATH 80 

/* First path sizes:
ESDIR/USERS/uid/uid_pass.txt
ESDIR/USERS/uid/uid_login.txt
ESDIR/USERS/uid/RESERVED
ESDIR/EVENTS/eid/START_eid.txt
ESDIR/EVENTS/eid/RES_eid.txt 
ESDIR/EVENTS/eid/RESERVATIONS
ESDIR/EVENTS/eid/DESCRIPTION
*/
#define SIZE_FRST_PATH 110 

/* Second path sizes:
ESDIR/USERS/uid/CREATED/eid.txt
ESDIR/USERS/uid/RESERVED/R-uid-date.txt
ESDIR/EVENTS/eid/DESCRIPTION/Fname
ESDIR/EVENTS/eid/RESERVATIONS/R-uid-date.txt
*/
#define SIZE_SCND_PATH 500 

#define SIZE_FILE_NAME 50

//--------------------------------------------------------------------
#define MAXBUF 256
#define CHUNK_SIZE 4096
#define MAXDIR 128
#define MAX
#define MAX_FILE_SIZE 10000000 // 10 MB
#define MAX_EVENT_ATTENDANCE 999
#define MIN_EVENT_ATTENDANCE 10
#define MAX_RESERVATIONS_PER_USER 999
#define MIN_RESERVATIONS_PER_USER 1
#define MAX_EID 999

//------------------------------- Msgs -------------------------------

// General
# define ERR_MSG "ERR\n"
#define OK_MSG "OK\n"
#define NLG_MSG "NLG\n"
#define WRP_MSG "WRP\n"

// Event creation
#define RCE_OK "RCE OK" // + EID
#define RCE_NOK "RCE NOK\n" // Event not created
#define RCE_NLG "RCE NLG\n" // User not logged in
#define RCE_WRP "RCE WRP\n" // Wrong password
#define RCE_ERR "RCE ERR\n"

// Event closure
#define RCL_OK "RCL OK\n"
#define RCL_NOK "RCL NOK\n" // User doesn't exist / Wrong password
#define RCL_NLG "RCL NLG\n" // User not logged in
#define RCL_NOE "RCL NOE\n" // Event EID doesn't exist
#define RCL_EOW "RCL EOW\n" // Event not created by User
#define RCL_SLD "RCL SLD\n" // Event created by user sold out
#define RCL_PST "RCL PST\n" // Event in the past
#define RCL_CLO "RCL CLO\n" // Event previously closed by user
#define RCL_ERR "RCL ERR\n"

// List
#define RLS_OK "RLS OK\n"
#define RLS_NOK "RLS NOK\n" // No event created
#define RLS_ERR "RLS ERR\n"
#define E_PAST 0 // Event in the past
#define E_FUT_NOT_SLD 1 // Event in the future, not sold out
#define E_FUT_SLD 2 // Event in the future, sold out
#define E_CLOSED 3 // Event closed by user

// Show
#define RSE_OK "RSE OK" // + info
#define RSE_NOK "RSE NOK\n"// File doesn't exist, event doesn't exist, other problem
#define RSE_ERR "RSE ERR\n"

// Reserve
#define RRI_NOK "RRI NOK\n" // Event not active
#define RRI_NLG "RRI NLG\n" // User not logged in
#define RRI_ACC "RRI ACC\n" // Event open, reservation accepted
#define RRI_CLS "RRI CLS\n" // Event closed
#define RRI_SLD "RRI SLD\n" // Event sold out
#define RRI_REJ "RRI REJ" // + remaining_seats // Reservation rejected (not enough seats)
#define RRI_PST "RRI PST\n" // Event in the past
#define RRI_WRP "RRI WRP\n" // Wrong password
#define RRI_ERR "RRI ERR\n"

// Change password
#define RCP_OK  "RCP OK\n" // Password changed successfully
#define RCP_WRP "RCP NOK\n" // Wrong password
#define RCP_NLG "RCP NLG\n" // User not logged in
#define RCP_NID "RCP NID\n" // User doesn't exist
#define RCP_ERR "RCP ERR\n"
