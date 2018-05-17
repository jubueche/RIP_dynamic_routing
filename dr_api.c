//TODO: Update timestamp to subnets that are directly connected

/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "dr_api.h"
#include "rmutex.h"

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20
#define RIP_GARBAGE_SEC 20

#define IPV4_ADDR_FAM 1 //NOTE: Not sure if needed
#define DEBUG 1

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
    uint16_t addr_family;
    uint16_t pad;           /* just put zero in this field */
    uint32_t ip;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
    char        command;
    char        version;
    uint16_t    pad;        /* just put zero in this field */
    rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
    uint32_t subnet;        /* destination subnet which this route is for */
    uint32_t mask;          /* mask associated with this route */
    uint32_t next_hop_ip;   /* next hop on on this route */
    uint32_t outgoing_intf; /* interface to use to send packets on this route */
    uint32_t cost;
    struct timeval last_updated;

    int is_garbage; /* boolean which notes whether this entry is garbage */

    route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
                               uint32_t next_hop_ip,
                               uint32_t outgoing_intf,
                               char* /* borrowed */,
                               unsigned);


/* internal functions */
long get_time();
void print_ip(int ip);
void print_routing_table(route_t *head);
/* internal lock-safe methods for the students to implement */
struct timeval get_struct_timeval();
void append(route_t *head, route_t *new_entry);
uint32_t count_route_table_entries();
void print_packet(rip_entry_t *packet);
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
void advertise_routing_table();
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                                  char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
    struct timespec timeout;

    timeout.tv_sec = secs_to_sleep_between_callbacks;
    timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
    while(1) {
        nanosleep(&timeout, NULL);
        dr_handle_periodic();
    }

    return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;
    rmutex_lock(&coarse_lock);
    hop = safe_dr_get_next_hop(ip);
    rmutex_unlock(&coarse_lock);
    return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_packet(ip, intf, buf, len);
    rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_periodic();
    rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
    rmutex_lock(&coarse_lock);
    safe_dr_interface_changed(intf, state_changed, cost_changed);
    rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */

/*Added variables*/
route_t *head_rt = NULL; //Head of the routing table

void dr_init(unsigned (*func_dr_interface_count)(),
             lvns_interface_t (*func_dr_get_interface)(unsigned index),
             void (*func_dr_send_payload)(uint32_t dst_ip,
                                          uint32_t next_hop_ip,
                                          uint32_t outgoing_intf,
                                          char* /* borrowed */,
                                          unsigned)) {
    pthread_t tid;

    /* save the functions the DR is providing for us */
    dr_interface_count = func_dr_interface_count;
    dr_get_interface = func_dr_get_interface;
    dr_send_payload = func_dr_send_payload;

    /* initialize the recursive mutex */
    rmutex_init(&coarse_lock);

    /* initialize the amount of time we want between callbacks */
    secs_to_sleep_between_callbacks = 1;
    nanosecs_to_sleep_between_callbacks = 0;

    /* start a new thread to provide the periodic callbacks */
    if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
        fprintf(stderr, "pthread_create failed in dr_initn");
        exit(1);
    }

    /* do initialization of your own data structures here */
    head_rt = (route_t *) malloc(sizeof(route_t));
    lvns_interface_t tmp;

    for(uint32_t i=0;i<dr_interface_count();i++){
      tmp = dr_get_interface(i);
      //if (DEBUG) print_ip(tmp.ip);
      route_t *new_entry = (route_t *) malloc(sizeof(route_t)); //DEBUG:Add catch of false malloc
      new_entry->subnet = tmp.subnet_mask & tmp.ip; //Destination
      new_entry->mask = tmp.subnet_mask;
      new_entry->next_hop_ip = 0; //NOTE: Not needed for initial, direct connections
      new_entry->outgoing_intf = i;
      new_entry->cost = tmp.cost;
      new_entry->last_updated = get_struct_timeval();
      new_entry->is_garbage = 0;
      new_entry->next = NULL;

      if(i==0){
        head_rt = new_entry;
      } else{
        append(head_rt, new_entry);
      }
    }
    if(DEBUG) print_routing_table(head_rt);
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;

    hop.interface = 0;
    hop.dst_ip = 0;

    /* determine the next hop in order to get to ip */
    route_t *current = head_rt;
    while(current != NULL){
      if((ip & current->mask) == current->subnet){
        hop.interface = current->outgoing_intf; //DEBUG: HTONL?
        hop.dst_ip = current->next_hop_ip; //DEBUG: HTONL?
        return hop; //There is only one entry to a certain IP/subnet
      }
      current = current->next;
    }
    hop.dst_ip = 0xFFFFFFFF;
    return hop;
}


void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                           char* buf /* borrowed */, unsigned len) {
    /* handle the dynamic routing payload in the buf buffer */
    //uint8_t offset = 0;
    rip_entry_t *received = (rip_entry_t *) malloc(sizeof(rip_entry_t));
    rip_header_t *header = (rip_header_t *) malloc(sizeof(rip_header_t));

    memcpy(header, buf, sizeof(rip_header_t));
    memcpy(received, buf + sizeof(rip_header_t), sizeof(rip_entry_t));

    //if (DEBUG) print_packet(received);

    /*Received a connection (u --> v) with a cost c(u,v), where u is the router it came from
    and v is another router or subnet.
    First: Check in the RT, if we have an entry where subnet == u. If yes, update the timestamp
    if not, make a new entry with the correct intfc, associated cost, and next_hop = 0.
    Second: For the (u,v) we have received, check if (Here, u) exists (must bcs. of First).
    If it exists, check if (Here, v) exists.
      If NO: Add a new entry (Here, v) with next_hop
        equal u with metric c(Here, u) + c(u,v).
      If YES: Compare c(Here,v) >? c(Here, u) + c(u,v)
          if we have found a better route, update the metric to c(Here, u) + c(u,v) */
    bool here_u_exists = false;
    bool here_v_exists = false;
    uint32_t v = received->ip;
    uint32_t u_interface_index = -1;
    route_t *current = head_rt;
    route_t *here_u;
    route_t *here_v;
    while(current != NULL){
      uint32_t end = current->subnet;
      if(end == ip){ //Is the endpoint of the entry the same as the IP that we are receiving this message from?
        here_u_exists = true;
        current->last_updated = get_struct_timeval(); //Reset the timestamp
        here_u = current;
        //fprintf(stderr, "%s\n", "Found Here -> u");
        /*Search the correct interface index*/
        for(uint32_t i=0;i<dr_interface_count();i++){
          lvns_interface_t tmp = dr_get_interface(i);
          if( (tmp.ip & tmp.subnet_mask)  == (here_u->subnet & tmp.subnet_mask) && tmp.enabled){
            u_interface_index = i;
          }
        }
      }
      if(end == v){
        here_v_exists = true;
        current->last_updated = get_struct_timeval();
        here_v = current;
        //fprintf(stderr, "%s\n", "Found Here -> v");
      }
      current = current->next;
    }
    if(!here_u_exists){ //This connection doesn't exist, add
      here_u = (route_t *) malloc(sizeof(route_t));
      here_u->subnet = ip;
      here_u->next_hop_ip = 0; //This is a direct connection
      for(uint32_t i=0;i<dr_interface_count();i++){
        lvns_interface_t tmp = dr_get_interface(i);
        if(((tmp.ip & tmp.subnet_mask) == received->ip) && tmp.enabled){ //We received drX --> drHere
          u_interface_index = i;
          //we have found the correct interface
          here_u->outgoing_intf = i;
          here_u->cost = tmp.cost;
          here_u->mask = tmp.subnet_mask;
          here_u->last_updated = get_struct_timeval();
          //Append to the list
          append(head_rt, here_u);
          if (DEBUG) fprintf(stderr, "%s\n", "Added a new entry to the RT.");
          print_routing_table(head_rt);
          here_u_exists = true;
          break;
        }
      }
    }
    if(!here_v_exists){ //TODO: Prevent from adding here -> v , where v is Here!
      here_v = (route_t *) malloc(sizeof(route_t));
      here_v->subnet = received->ip; //received = u -> v
      here_v->mask = received->subnet_mask;
      here_v->next_hop_ip = ip; //Hop to u first
      here_v->outgoing_intf = u_interface_index; //Intf index to send out packets to u
      here_v->cost = here_u->cost + received->metric;
      here_v->last_updated = get_struct_timeval();
      here_v->is_garbage = 0;
      here_v->next = NULL;
      append(head_rt, here_v);
      here_v_exists = true;
      fprintf(stderr, "%s\n", "Added here -> v");
      print_routing_table(head_rt);
    } else{ /*Bellman Ford update*/
      if(here_v->cost > here_u->cost + received->metric){
        fprintf(stderr, "%s\n", "Updated Here -> ");
        print_ip(here_v->subnet);
        print_routing_table(head_rt);
        here_v->cost = here_u->cost + received->metric;
        here_v->outgoing_intf = u_interface_index;
        here_v->next_hop_ip = here_u->subnet;
        here_v->mask = here_u->mask;
      }
    }

    free(header);
    free(received);
}

//TODO: For all directly connected subnets, check if the interface is enabled and reset the timer
void safe_dr_handle_periodic() {
    /* handle periodic tasks for dynamic routing here */
    /*Send out the complete routing table to neighbors*/
    advertise_routing_table();

    long current_time;
    route_t *current = head_rt;
    while(current != NULL){
      current_time = get_time();
      long time_entry = current->last_updated.tv_sec * 1000 + current->last_updated.tv_usec / 1000;
      if((current_time - time_entry)/1000.f > RIP_GARBAGE_SEC && current->is_garbage != 1){ //Convert difference to seconds
        current->is_garbage = 1;
        if(DEBUG) fprintf(stderr, "%s\n", "PT entry -> garbage");
      }
      current = current->next;
    }

}

static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed) {
    /* handle an interface going down or being brought up */
}

/* definition of internal functions */

// gives current time in milliseconds
long get_time(){
    // Now in milliseconds
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}

void append(route_t *head, route_t *new_entry){
  route_t *current = head;

  while (current->next != NULL) {
      current = current->next;
  }
  current->next = (route_t *) malloc(sizeof(route_t)); //DEBUG:Add catch of false malloc
  current->next = new_entry;
}

void advertise_routing_table(){
  route_t *current;
  for(uint32_t i=0;i<dr_interface_count();i++){
    current = head_rt;
    while(current != NULL){
      rip_entry_t *packet = (rip_entry_t *) malloc(sizeof(rip_entry_t));
      rip_header_t *header = (rip_header_t *) malloc(sizeof(rip_header_t));
      packet->addr_family = IPV4_ADDR_FAM;
      packet->pad = 0;
      packet->ip = current->subnet;
      packet->subnet_mask = current->mask;
      packet->next_hop = current->next_hop_ip;
      packet->metric = current->cost;
      header->command = RIP_COMMAND_RESPONSE;
      header->version = RIP_VERSION;
      header->pad = 0;
      //DEBUG: I don't initialize entries[0] here, since it is an empty array, why?

      char buf[sizeof(*header) + sizeof(*packet)];
      memcpy(buf, header, sizeof(*header));
      memcpy(buf + sizeof(*header), packet, sizeof(*packet));

      dr_send_payload(RIP_IP, RIP_IP, i,buf,sizeof(buf));

      //if(DEBUG) fprintf(stderr, "%s\n", "Send package: ");
      //if(DEBUG) print_packet(packet);
      free(packet);
      free(header);

      current = current->next;
    }
  }
}

void print_packet(rip_entry_t *packet){
  fprintf(stderr, " Packet IP: ");
  print_ip(packet->ip);
  fprintf(stderr, " Subnet mask: ");
  print_ip(packet->subnet_mask);
  fprintf(stderr, " Next hop: ");
  print_ip(packet->next_hop);
}

uint32_t count_route_table_entries(){
  uint32_t cnt = 0;
  route_t *current = head_rt;

  while (current->next != NULL) {
    cnt++;
    current = current->next;
  }
  return cnt;
}

struct timeval get_struct_timeval(){
  struct timeval now;
  gettimeofday(&now, NULL);
  return now;
}

// prints an ip address in the correct format
// this function is taken from:
// https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}

// prints the full routing table
void print_routing_table(route_t *head){
    printf("==================================================================\nROUTING TABLE:\n==================================================================\n");
    int counter = 0;
    route_t *current = head;
    while (current != NULL){
        printf("Entry %d:\n",counter);
        printf("\tSubnet: ");
        print_ip(current->subnet);
        printf("\tMask: ");
        print_ip(current->mask);
        printf("\tNext hop ip: ");
        print_ip(current->next_hop_ip);
        printf("\tOutgoing interface: ");
        print_ip(current->outgoing_intf);
        printf("\tCost: %d\n", current->cost);
        printf("\tLast updated (timestamp in microseconds): %li \n", current->last_updated.tv_usec);
        printf("==============================\n");
        counter ++;

        current = current->next;
    }
}
