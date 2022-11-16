/*
 * Bluetool the ultimate bluetooth tool 
 * by sha0coder
 *
 *
 * Compilation:
 *   sudo apt-get install libbluetooth-dev
 *   gcc -o bluetool bluetool.c -lbluetooth -O2 -g
 *
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

float VERSION = 0.1;
char VERBOSE = 0;

int blue_scan(int dev_id) {
    inquiry_info *ii = NULL;
    int max_rsp, num_rsp;
    int sock, len, flags;
    int i;
    char addr[19] = { 0 };
    char name[248] = { 0 };

    printf("scanning the air ...\n");

    sock = hci_open_dev( dev_id );
    if (dev_id < 0 || sock < 0) {
        perror("opening socket");
        exit(1);
    }

    len  = 8;
    max_rsp = 255;
    flags = IREQ_CACHE_FLUSH;
    ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));

    num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &ii, flags);
    if( num_rsp < 0 ) perror("hci_inquiry");

    printf("bluetooth remote devices:\n");
    for (i = 0; i < num_rsp; i++) {
        ba2str(&(ii+i)->bdaddr, addr);
        memset(name, 0, sizeof(name));
        if (hci_read_remote_name(sock, &(ii+i)->bdaddr, sizeof(name),
            name, 0) < 0)
        strcpy(name, "[unknown]");
        printf(" %s  %s rep:%u period:%u mode:%u class:%u.%u.%u clock:%u\n",
        addr, name, *&(ii+i)->pscan_rep_mode, *&(ii+i)->pscan_period_mode, *&(ii+i)->pscan_mode,
        *&(ii+i)->dev_class[0], *&(ii+i)->dev_class[1], *&(ii+i)->dev_class[2]), *&(ii+i)->clock_offset;
    }

    free( ii );
    close( sock );
    printf("---\n\n");
    return 0;
}

int blue_lescan(int dev_id) {
  int sock;
  size_t n;
  char buff[261];
  char opts[16];
  struct iovec iov[3];
  struct sockaddr_hci hci;

  hci.hci_family = AF_BLUETOOTH;
  hci.hci_dev = htobs(dev_id);
  hci.hci_channel = HCI_CHANNEL_RAW;

  sock = socket(AF_BLUETOOTH, SOCK_RAW|SOCK_CLOEXEC, BTPROTO_HCI);
  if (sock < 0) {
    perror("socket error\n");
    return;
  }

  n = bind(sock, &hci, 6);
  if (n < 0) {
    perror("bind error\n");
    return;
  }
  
  iov[0].iov_base = "\1";
  iov[0].iov_len = 1;
  iov[1].iov_base = "\v \7";
  iov[1].iov_len = 3;
  iov[2].iov_base = "\1\20\0\20\0\0\0";
  iov[2].iov_len = 7;

  strncpy(opts, "\20\0\0\0\1\300\0\0\0\0\0@\v \0\0", 16);
  setsockopt(sock, SOL_IP, IP_TTL, &opts, 16);
  n = writev(sock, &iov, 3);
  if (n < 0) {
    perror("writev error\n");
    return;
  }

  n = read(sock, buff, 260);
  if (n < 0) {
    perror("read error\n");
    return;
  }
  printf("%d bytes read\n");

  iov[0].iov_base = "\1";
  iov[0].iov_len = 1;
  iov[1].iov_base = "\f \2";
  iov[1].iov_len = 3;
  iov[2].iov_base = "\1\1";
  iov[2].iov_len = 2;

  strncpy(opts, "\20\0\0\0\1\300\0\0\0\0\0@\f \0\0", 16);
  setsockopt(sock, SOL_IP, IP_TTL, &opts, 16);
  n = writev(sock, &iov, 3);
  if (n < 0) {
    perror("writev error\n");
    return;
  }

  buff[260] = 0x00; 
  n = read(sock, buff, 260);
  if (n < 0) {
    perror("read error\n");
    return;
  }


  strncpy(opts, "\20\0\0\0\0\0\0\0\0\0\0@\0\0\0\0", 16);
  setsockopt(sock, SOL_IP, IP_TTL, &opts, 16);

  while (1) {
    n = read(sock, buff, 260);
    if (n < 0) {
      perror("read error\n");
      return;
    }

    printf("%s\n", buff);
  }



  /*
  getsockopt(sock, SOL_IP, IP_TTL, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", [16]) = 0
  setsockopt(sock, SOL_IP, IP_TTL, "\20\0\0\0\1\300\0\0\0\0\0@\v \0\0", 16) = 0

  writev(sock, [{iov_base="\1", iov_len=1}, {iov_base="\v \7", iov_len=3}, {iov_base="\1\20\0\20\0\0\0", iov_len=7}], 3) 
  poll([{fd=sock, events=POLLIN}], 1, 10000) = 1 ([{fd=3, revents=POLLIN}])
  read(sock, "\4\16\4\1\v \0", 260)          = 7
  setsockopt(sock, SOL_IP, IP_TTL, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) = 0
  getsockopt(sock, SOL_IP, IP_TTL, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", [16]) = 0
  setsockopt(sock, SOL_IP, IP_TTL, "\20\0\0\0\1\300\0\0\0\0\0@\f \0\0", 16) = 0
  writev(sock, [{iov_base="\1", iov_len=1}, {iov_base="\f \2", iov_len=3}, {iov_base="\1\1", iov_len=2}], 3) = 6
  poll([{fd=sock, events=POLLIN}], 1, 10000) = 1 ([{fd=3, revents=POLLIN}])
  read(sock, "\4\16\4\2\f \0", 260)          = 7
  setsockopt(sock, SOL_IP, IP_TTL, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) = 0
  getsockopt(sock, SOL_IP, IP_TTL, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", [16]) = 0
  setsockopt(sock, SOL_IP, IP_TTL, "\20\0\0\0\0\0\0\0\0\0\0@\0\0\0\0", 16) = 0
  rt_sigaction(SIGINT, {sa_handler=0x55f9862b9db0, sa_mask=[], sa_flags=SA_RESTORER|SA_NOCLDSTOP, sa_restorer=0x7f3b68f60890}, NULL, 8) = 0
  read(3, "\4>\32\2\1\0\1\20\222n\266+V\16\2\1\32\n\377L\0\20\5\q3\34\353\261\263\302", 260) = 29
  */


  close(sock);
}

int blue_hidden_scan(int dev_id) {
  int sock;
  char addr[19] = { 0 };
  char name[248] = { 0 };
  unsigned int i[6];
  bdaddr_t bdaddr;

  sock = hci_open_dev( dev_id );
  if (dev_id < 0 || sock < 0) {
      perror("opening socket");
      exit(1);
  }

  printf("detecting hidden devices:\n"); //TODO: concurrent
  for (i[0]=0; i[0]<0xff; i[0]++) {
    bdaddr.b[0] = i[0];
    for (i[1]=0; i[1]<0xff; i[1]++) {
      bdaddr.b[1] = i[1];
      for (i[2]=0; i[2]<0xff; i[2]++) {
        bdaddr.b[2] = i[2];
        for (i[3]=0; i[3]<0xff; i[3]++) {
          bdaddr.b[3] = i[3];
          for (i[4]=0; i[4]<0xff; i[4]++) {
            bdaddr.b[4] = i[4];
            for (i[5]=0; i[5]<0xff; i[5]++) {
              bdaddr.b[5] = i[5];


              if (hci_read_remote_name(sock, &bdaddr, sizeof(name), name, 0) >= 0) {
                ba2str(&bdaddr, addr);
                printf(" [+] %s %s\n", addr, name);
              } /*else {
                ba2str(&bdaddr, addr);
                printf(" fail %s\n", addr);
              }*/

            }
          }
        }
      }
      printf(" %x:%x...\n", i[0], i[1]);
    }
    printf(" %x:...\n", i[0]);
  }

  close(sock);
  printf("---\n\n");
  return 0;
}

void enum_interfaces() {
  int sock, dev_id;

  printf("bluetooth interfaces:\n");
  for (dev_id=0; dev_id<0xffff; dev_id++) {
    sock = hci_open_dev(dev_id);
    if (sock >= 0) {
      printf(" device id: %d\n", dev_id);
      close(sock);
    }
  }
  printf("---\n\n");
}

void check_sock(int sock) {
  if (sock < 0) {
      perror("opening socket");
      exit(1);
  }
}

int prepare_rfcomm_socket() {
  int sock;
  sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
  check_sock(sock);
  return sock;
}

int prepare_l2cap_socket() {
  int sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
  check_sock(sock);
  return sock;
}


int rfcomm_channel_scan(int dev_id, char *target) {
  int sock, sz, buff_sz, stat;
  char *buff;
  struct sockaddr_rc addr = { 0 };
  uint8_t channel=0;

  buff_sz = 1024;
  buff = (char *)malloc(buff_sz);


  addr.rc_family = AF_BLUETOOTH;
  str2ba(target, &addr.rc_bdaddr);

  printf("scanning rfcomm channels:\n");
  for (addr.rc_channel=0; addr.rc_channel<0xff; addr.rc_channel++) {
    sock = prepare_rfcomm_socket();
    printf("channel: %d\n", addr.rc_channel);
    stat = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (stat==0) {
      printf(" channel %u open\n", channel);
      sz = write(sock, "\r\n\r\n", 4);
      printf("    sent %d bytes\n", sz);
      memset(buff, 0, buff_sz);
      sz = recv(sock, buff, buff_sz, 0);
      printf("    received %d bytes, banner: [%s]\n", sz, buff);
    }

    close(sock);
  }

  free(buff);
  printf("---\n");
  return 0;
}

int l2cap_psm_comm(int dev_id, char *target, int psm, char *data) {
  struct sockaddr_l2 addr = { 0 };
  unsigned long buff_sz = 1024;
  char *buff;
  int sock, stat, sent, rb;

  buff = (char *)malloc(buff_sz);
  addr.l2_family = AF_BLUETOOTH;
  str2ba(target, &addr.l2_bdaddr);
  sock = prepare_l2cap_socket();
  addr.l2_psm = htobs((unsigned short)psm);
  printf("connecting ...\n");
  stat = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
  if (stat != 0) {
      printf("cannot connect\n");
      close(sock);
      return 0;
  }

  printf("connected.\n");
  sent = send(sock, data, strlen(data), 0);
  printf("%d bytes sent\n", sent);
  rb = recv(sock, buff, buff_sz, 0);
  printf("%d bytes received: %s\n", rb, buff);
  close(sock); 
}

int l2cap_psm_scan(int dev_id, char *target) {
  struct sockaddr_l2 addr = { 0 };
  char *buff;
  int sock, stat, buff_sz, sz;
  unsigned short psm;

  buff_sz = 1024;
  buff = (char *)malloc(buff_sz);

  addr.l2_family = AF_BLUETOOTH;
  str2ba(target, &addr.l2_bdaddr);

  printf("open psm's:\n");
  for (psm=0; psm<0xffff; psm++) {
    sock = prepare_l2cap_socket();
    printf("psm: %u\n", psm);
    addr.l2_psm = htobs(psm);

    stat = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (stat==0) {
      printf(" psm %u open\n", psm);
    }

    close(sock);
  }

  free(buff);
  printf("---\n");
  return 0;
}

int command_fuzzer(int dev_id, char *target) {
  int err = 0, dd;
  struct hci_conn_info_req *cr = 0;
  struct hci_request rq = { 0 };
  int timeout=10;

  struct {
        uint16_t handle;
        uint16_t flush_timeout;
  } cmd_param;

  struct {
      uint8_t  status;
      uint16_t handle;
  } cmd_response;

  dd = hci_open_dev(dev_id);

  cr = (struct hci_conn_info_req*) malloc(
          sizeof(struct hci_conn_info_req) +
          sizeof(struct hci_conn_info));
  str2ba(target, &cr->bdaddr);
  cr->type = ACL_LINK;

  err = ioctl(dd, HCIGETCONNINFO, (unsigned long)cr);
  if( err ) goto cleanup;

  printf("command fuzzing endless loop ...\n");
  while (1) {
    cmd_param.handle = cr->conn_info->handle;
    cmd_param.flush_timeout = htobs(rand());
    rq.ogf =  rand()%0xffff; //OGF_HOST_CTL;  uint16_t
    rq.ocf = 0x28;
    rq.cparam = &cmd_param;
    rq.clen = sizeof(cmd_param);
    rq.rparam = &cmd_response;
    rq.rlen = sizeof(cmd_response);
    rq.event = rand();  //EVT_CMD_COMPLETE;

    err = hci_send_req( dd, &rq, 0 );
    if (!err) {
      printf("ok status:%2x\n",cmd_response.status);
    }

    if (cmd_response.status) {
        err = -1;
        errno = bt_error(cmd_response.status);
    }
  }

cleanup:
  free(cr);
  if(dd >= 0) close(dd);
  return err;
}

int uuid_scan(int dev_id, char *target) {
    uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xab, 0xcd };
    uuid_t svc_uuid;
    int err;
    bdaddr_t btarget;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    sdp_session_t *session = 0;

    str2ba(target, &btarget);
    session = sdp_connect(BDADDR_ANY, &btarget, SDP_RETRY_IF_BUSY);
    printf("conectado %d\n",session);

    // set the uuid
    sdp_uuid128_create( &svc_uuid, &svc_uuid_int );
    printf("1\n");
    search_list = sdp_list_append( NULL, &svc_uuid );
    printf("2\n");

    // all application atributes
    uint32_t range = 0x0000ffff;
    attrid_list = sdp_list_append( NULL, &range );
    printf("3\n");

    // get a list of service records that have UUID 0xabcd
    err = sdp_service_search_attr_req( session, search_list, \
        SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
        printf("4\n");

    // parse output:
        sdp_list_t *r = response_list;

    // go through each of the service records
    for (; r; r = r->next ) {
        sdp_record_t *rec = (sdp_record_t*) r->data;
        sdp_list_t *proto_list;

        // get a list of the protocol sequences
        if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
        sdp_list_t *p = proto_list;

        // go through each protocol sequence
        for( ; p ; p = p->next ) {
            sdp_list_t *pds = (sdp_list_t*)p->data;

            // go through each protocol list of the protocol sequence
            for( ; pds ; pds = pds->next ) {

                // check the protocol attributes
                sdp_data_t *d = (sdp_data_t*)pds->data;
                int proto = 0;
                for( ; d; d = d->next ) {
                    switch( d->dtd ) {
                        case SDP_UUID16:
                        case SDP_UUID32:
                        case SDP_UUID128:
                            proto = sdp_uuid_to_proto( &d->val.uuid );
                            break;
                        case SDP_UINT8:
                            if( proto == RFCOMM_UUID ) {
                                printf("rfcomm channel: %d\n",d->val.int8);
                            }
                            break;
                    }
                }
            }
            sdp_list_free( (sdp_list_t*)p->data, 0 );
        }
        sdp_list_free( proto_list, 0 );

        }

        printf("found service record 0x%x\n", rec->handle);
        sdp_record_free( rec );
    }

    sdp_close(session);
}



void usage() {
  printf("bluetool v%.2f usage:\n\n", VERSION);
  printf(" ./bluetool [mode] (interface) (target)\n");
  printf("examples:\n");
  printf(" ./bluetool i                                 enum bluetooth local interfaces\n");
  printf(" ./bluetool s 0                               scan devices throught the interface 0\n");
  printf(" ./bluetool e 0                               scan devices throught the interface 0\n");
  printf(" ./bluetool h 0                               scan hidden devices (very slow)\n");
  printf(" ./bluetool r 0 11:22:33:44:55:66             rfcomm channel scan (noisy)\n");
  printf(" ./bluetool l 0 11:22:33:44:55:66             l2cap psm scan\n");
  printf(" ./bluetool p 0 11:22:33:44:55:66 psm data    l2cap psm send data\n");
  printf(" ./bluetool c 0 11:22:33:44:55:66             low level command fuzzer\n");
  printf(" ./bluetool u 0 11:22:33:44:55:66             services uuid scan\n");

  printf("\n");
  exit(1);
}

int main(int argc, char **argv) {
  int mode;
  int dev_id;
  time_t t;

  if (argc < 4)
    usage();


  srand((unsigned) time(&t));

  mode = (int)argv[1][0];
  switch(mode) {
    case 'i': enum_interfaces(); return 0;
    case 's': if (argc!=3) usage(); return blue_scan(atoi(argv[2]));
    case 'e': if (argc!=3) usage(); return blue_lescan(atoi(argv[2]));
    case 'h': if (argc!=3) usage(); return blue_hidden_scan(atoi(argv[2]));
    case 'r': if (argc!=4) usage(); return rfcomm_channel_scan(atoi(argv[2]), argv[3]);
    case 'l': if (argc!=4) usage(); return l2cap_psm_scan(atoi(argv[2]), argv[3]);
    case 'c': if (argc!=4) usage(); return command_fuzzer(atoi(argv[2]), argv[3]);
    case 'u': if (argc!=4) usage(); return uuid_scan(atoi(argv[2]), argv[3]);
    case 'p': if (argc!=6) usage(); return l2cap_psm_comm(atoi(argv[2]), argv[3], atoi(argv[4]), argv[5]);
    default: usage();
  }
}
