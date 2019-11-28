#ifdef __Nautilus__
#include "memcached.h"

#include <nautilus/shell.h>

#else
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <sys/uio.h>
#include <fcntl.h>

#include "memcached.h"
#endif



struct settings settings;
static bool stop_main_loop = false;
//volatile rel_time_t current_time; 

conn **conns;

//#define MEMCACHED_HOST "127.0.0.1"
#define MEMCACHED_HOST "172.16.67.146" 

#define CONN_RUNNING 0
#define CONN_CLOSING 1

#ifndef IOV_MAX
# define IOV_MAX 1024
#endif

enum try_read_result {
    READ_DATA_RECEIVED,
    READ_NO_DATA_RECEIVED,
    READ_ERROR,            /** an error occurred (on the socket) (or client closed connection) */
    READ_MEMORY_ERROR      /** failed to allocate more memory */
};

enum transmit_result {
    TRANSMIT_COMPLETE,   /** All done writing. */
    TRANSMIT_INCOMPLETE, /** More data remaining to write. */
    TRANSMIT_SOFT_ERROR, /** Can't write any more right now. */
    TRANSMIT_HARD_ERROR  /** Can't write (c->state is set to conn_closing) */
};

ssize_t memcached_tcp_read(conn *c, void *buf, size_t count) { 
    assert (c != NULL);
    return read(c->sfd, buf, count);
}
ssize_t memcached_tcp_sendmsg(conn *c, struct msghdr *msg, int flags) {
    assert (c != NULL);
    return sendmsg(c->sfd, msg, flags);
}   
ssize_t memcached_tcp_write(conn *c, void *buf, size_t count) {
    assert (c != NULL);
    return write(c->sfd, buf, count);
}

static int add_msghdr(conn *c)
{
    struct msghdr *msg;

    if (c->msgsize == c->msgused) {
        msg = realloc(c->msglist, c->msgsize * 2 * sizeof(struct msghdr));
        if (! msg) {
            return -1;
        }
        c->msglist = msg;
        c->msgsize *= 2;
    }

    msg = c->msglist + c->msgused;

    /* this wipes msg_iovlen, msg_control, msg_controllen, and
       msg_flags, the last 3 of which aren't defined on solaris: */
    memset(msg, 0, sizeof(struct msghdr));

    msg->msg_iov = &c->iov[c->iovused];

    c->msgbytes = 0;
    c->msgused++;

    return 0;
}

static int ensure_iov_space(conn *c) {
    assert(c != NULL);

    if (c->iovused >= c->iovsize) {
        int i, iovnum;
        struct iovec *new_iov = (struct iovec *)realloc(c->iov,
                                (c->iovsize * 2) * sizeof(struct iovec));
        if (! new_iov) {
            return -1;
        }
        c->iov = new_iov;
        c->iovsize *= 2;

        /* Point all the msghdr structures at the new list. */
        for (i = 0, iovnum = 0; i < c->msgused; i++) {
            c->msglist[i].msg_iov = &c->iov[iovnum];
            iovnum += c->msglist[i].msg_iovlen;
        }
    }

    return 0;
}

static int add_iov(conn *c, const void *buf, int len) {
    struct msghdr *m;
    int leftover;

    /* Optimized path for TCP connections */
    m = &c->msglist[c->msgused - 1];
    if (m->msg_iovlen == IOV_MAX) {
        add_msghdr(c);
        m = &c->msglist[c->msgused - 1];
    }

    if (ensure_iov_space(c) != 0)
        return -1;

    m->msg_iov[m->msg_iovlen].iov_base = (void *)buf;
    m->msg_iov[m->msg_iovlen].iov_len = len;
    c->msgbytes += len;
    c->iovused++;
    m->msg_iovlen++;
    return 0;
}

static int add_chunked_item_iovs(conn *c, item *it, int len) {
    assert(it->it_flags & ITEM_CHUNKED);
    item_chunk *ch = (item_chunk *) ITEM_schunk(it);
    while (ch) {
        int todo = (len > ch->used) ? ch->used : len;
        if (add_iov(c, ch->data, todo) != 0) {
            return -1;
        }
        ch = ch->next;
        len -= todo;
    }
    return 0;
}

static void add_bin_header(conn *c, uint16_t err, uint8_t hdr_len, uint16_t key_len, uint32_t body_len) {
    protocol_binary_response_header* header;

    assert(c);

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        /* This should never run out of memory because iov and msg lists
         * have minimum sizes big enough to hold an error response.
         */
        //out_of_memory(c, "SERVER_ERROR out of memory adding binary header");
        return;
    }

    header = (protocol_binary_response_header *)c->wbuf;

    header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
    header->response.opcode = c->binary_header.request.opcode;
    header->response.keylen = (uint16_t)htons(key_len);

    header->response.extlen = (uint8_t)hdr_len;
    header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
    header->response.status = (uint16_t)htons(err);

    header->response.bodylen = htonl(body_len);
    header->response.opaque = c->opaque;
    header->response.cas = htonll(c->cas);

    if (settings.verbose > 2) {
        int ii;
        fprintf(stderr, ">%d Writing bin response:", c->sfd);
        for (ii = 0; ii < sizeof(header->bytes); ++ii) {
            if (ii % 4 == 0) {
                fprintf(stderr, "\n>%d  ", c->sfd);
            }
            fprintf(stderr, " 0x%02x", header->bytes[ii]);
        }
        fprintf(stderr, "\n");
    }


    add_iov(c, c->wbuf, sizeof(header->response));
}

static enum transmit_result transmit(conn *c) {
    if (c->msgcurr < c->msgused && c->msglist[c->msgcurr].msg_iovlen == 0) {
        /* Finished writing the current msg; advance to the next. */
        c->msgcurr++;
    }

    // transmit until done
    while (c->msgcurr < c->msgused) {
        ssize_t res;
        struct msghdr *m = &c->msglist[c->msgcurr];

#ifdef __Nautilus__
        res = c->nk_sendmsg(c, m, 0);
#else
        res = c->sendmsg(c, m, 0);
#endif
        if (res >= 0) {
            /* We've written some of the data. Remove the completed
               iovec entries from the list of pending writes. */
            while (m->msg_iovlen > 0 && res >= m->msg_iov->iov_len) {
                res -= m->msg_iov->iov_len;
                m->msg_iovlen--;
                m->msg_iov++;
            }
            /* Might have written just part of the last iovec entry;
               adjust it so the next write will do the rest. */
            if(res > 0) {
                m->msg_iov->iov_base = (caddr_t)m->msg_iov->iov_base + res;
                m->msg_iov->iov_len -= res;
            }
        }
        if (res == -1
                && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
            printf("%s sendmsg error %d\n", __FUNCTION__, errno);
            // should close
            return TRANSMIT_HARD_ERROR;
        }
        if (c->msgcurr < c->msgused && c->msglist[c->msgcurr].msg_iovlen == 0) {
            /* Finished writing the current msg; advance to the next. */
            c->msgcurr++;
        }
    }
    return TRANSMIT_COMPLETE;
}

static int  handle_conn_mwrite(conn *c) {
    switch (transmit(c)) {
        case TRANSMIT_COMPLETE:
            return 0;
            break;
        case TRANSMIT_INCOMPLETE:
            // should not happen
            break;
        case TRANSMIT_SOFT_ERROR:
        case TRANSMIT_HARD_ERROR:
            return -1;
            break;
    }
    return 0;
}

static int write_bin_error(conn *c, protocol_binary_response_status err,
                            const char *errstr, int swallow) {
    size_t len;

    if (!errstr) {
        switch (err) {
        case PROTOCOL_BINARY_RESPONSE_ENOMEM:
            errstr = "Out of memory";
            break;
        case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
            errstr = "Unknown command";
            break;
        case PROTOCOL_BINARY_RESPONSE_KEY_ENOENT:
            errstr = "Not found";
            break;
        case PROTOCOL_BINARY_RESPONSE_EINVAL:
            errstr = "Invalid arguments";
            break;
        case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
            errstr = "Data exists for key.";
            break;
        case PROTOCOL_BINARY_RESPONSE_E2BIG:
            errstr = "Too large.";
            break;
        case PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL:
            errstr = "Non-numeric server-side value for incr or decr";
            break;
        case PROTOCOL_BINARY_RESPONSE_NOT_STORED:
            errstr = "Not stored.";
            break;
        case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
            errstr = "Auth failure.";
            break;
        default:
            assert(false);
            errstr = "UNHANDLED ERROR";
            fprintf(stderr, ">%d UNHANDLED ERROR: %d\n", c->sfd, err);
        }
    }

    len = strlen(errstr);
    add_bin_header(c, err, 0, 0, len);
    if (len > 0) {
        add_iov(c, errstr, len);
    }
    //conn_set_state(c, conn_mwrite);
    return handle_conn_mwrite(c);
/*
    if(swallow > 0) {
        c->sbytes = swallow;
        c->write_and_go = conn_swallow;
    } else {
        c->write_and_go = conn_new_cmd;
    }
    */
}

/* Form and send a response to a command over the binary protocol */
static int write_bin_response(conn *c, void *d, int hlen, int keylen, int dlen) {
    if (1||c->cmd == PROTOCOL_BINARY_CMD_GET) {
        add_bin_header(c, 0, hlen, keylen, dlen);
        if(dlen > 0) {
            add_iov(c, d, dlen);
        }
        //conn_set_state(c, conn_mwrite);
        return handle_conn_mwrite(c);
        //c->write_and_go = conn_new_cmd;
    } else {
        //conn_set_state(c, conn_new_cmd);
        return 0;
    }
}

static int write_bin_miss_response(conn *c, char *key, size_t nkey) {
    if (nkey) {
        char *ofs = c->wbuf + sizeof(protocol_binary_response_header);
        add_bin_header(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0, nkey, nkey);
        memcpy(ofs, key, nkey);
        add_iov(c, ofs, nkey);
        //conn_set_state(c, conn_mwrite);
        //c->write_and_go = conn_new_cmd;
        return handle_conn_mwrite(c);
    } else {
        return write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
    }
}

// create, bind and listen on socket
static int server_socket(int port) {
    int acc_sock;
    int error;
    int flags = 1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    //addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(MEMCACHED_HOST);

    if ((acc_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Failed to connect socket on port %d\n", port);
        return -1;
    }

#if 0
    if ((flags = fcntl(acc_sock, F_GETFL, 0)) < 0 ||
            fcntl(acc_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("setting O_NONBLOCK");
        close(acc_sock);
        return -1;
    }
#endif
    if(0 != setsockopt(acc_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags))) {
        printf("Failed to set SO_REUSEADDR err %d\n", errno);
        return -1;
    }
    if(0 != setsockopt(acc_sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags))) {
        printf("Failed to set SO_KEEPALIVE err %d\n", errno);
        return -1;
    }
#if 0
    if(0 != setsockopt(acc_sock, SOL_SOCKET, SO_LINGER, (void *)&flags, sizeof(flags))) {
        printf("Failed to set SO_LINGER err %d\n", errno);
        return -1;
    }
#endif
#if 0
    if(0 != setsockopt(acc_sock, SOL_SOCKET, TCP_NODELAY, (void *)&flags, sizeof(flags))) {
        printf("Failed to set TCP_NODELAY err %d\n", errno);
        return -1;
    }
#endif
    if(-1 == bind(acc_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
        printf("Failed to bind socket on port %d\n", port);
        return -1;
    }

    if(-1 == listen(acc_sock, 1024)) {
        printf("Failed to listen socket on port %d err %d\n", port, errno);
        return -1;
    }

    return acc_sock;
}

#define REALTIME_MAXDELTA 60*60*24*30 // 30 days
time_t process_started;     /* when the process was started */

static rel_time_t realtime(const time_t exptime) {
    if (exptime == 0) return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA) {
        if (exptime <= process_started)
            return (rel_time_t)1;
        return (rel_time_t)(exptime - process_started);
    } else {
        return (rel_time_t)(exptime + current_time);
    }
}

static void conn_cleanup(conn *c) {

}

static void conn_close(conn *c) {
    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    conn_cleanup(c);
    close(c->sfd);
}

static void conn_free(conn *c) {
    if(c) {
        if(c->rbuf)
            free(c->rbuf);
        if(c->wbuf)
            free(c->wbuf);
        if(c->iov)
            free(c->iov);
        if(c->msglist)
            free(c->msglist);
        free(c);    
    }
}

static int conn_init() {
    if ((conns = calloc(settings.maxconns, sizeof(conn *))) == NULL) {
        fprintf(stderr, "Failed to allocate connection structures\n");
        /* This is unrecoverable so bail out early. */
        return -1;
    }
    return 0;
}

conn *conn_new(const int sfd, int read_buffer_size) {
    conn *c = conns[sfd];
    if (NULL == c) {
        if(!(c = (conn *)calloc(1, sizeof(conn)))) {
            fprintf(stderr, "Failed to allocate connection object\n");
            return NULL;
        }
#ifdef __Nautilus__
        c->nk_read = memcached_tcp_read;
        c->nk_sendmsg = memcached_tcp_sendmsg;
        c->nk_write = memcached_tcp_write;
#else
        c->read = memcached_tcp_read;
        c->sendmsg = memcached_tcp_sendmsg;
        c->write = memcached_tcp_write;
#endif
        c->iov = 0;

        c->rsize = read_buffer_size;
        c->wsize = DATA_BUFFER_SIZE;
        c->iovsize = IOV_LIST_INITIAL;
        c->msgsize = MSG_LIST_INITIAL;


        if((c->rbuf = (char *)malloc((size_t)c->rsize)) == NULL 
                || (c->wbuf = (char *)malloc((size_t)c->wsize)) == NULL
                || (c->msglist = (struct msghdr *)malloc(sizeof(struct msghdr) * c->msgsize)) == NULL
                || (c->iov = (struct iovec *)malloc(sizeof(struct iovec) * c->iovsize)) == NULL) {
            conn_free(c);
            fprintf(stderr, "Failed to allocate buffers for connection\n");
            return NULL;
        }

        c->sfd = sfd;
    }

    // get peer
    if (getpeername(sfd, (struct sockaddr *) &c->request_addr,
                &c->request_addr_size)) {
        memset(&c->request_addr, 0, sizeof(c->request_addr));
    }

    c->rbytes = 0; // amount of bytes read
    c->iovused = 0;
    c->msgcurr = 0;
    c->msgused = 0;
    c->rcurr = c->rbuf;

    return c;
}

// read all data from the conn
static enum try_read_result try_read_network(conn *c) {
    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
    int res;
#if 1
    if (c->rcurr != c->rbuf) {
        if (c->rbytes != 0) {/* otherwise there's nothing to copy */
            //fprintf(stderr, "%s: rbytes %d\n", __FUNCTION__, c->rbytes); 
            memmove(c->rbuf, c->rcurr, c->rbytes);
        }
        c->rcurr = c->rbuf;
    }
#endif
    while (1) {
        if (c->rbytes >= c->rsize) {
            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
            if (!new_rbuf) {
                c->rbytes = 0; /* ignore what we read */
                return -1;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        int avail = c->rsize - c->rbytes;
#ifdef __Nautilus__
        res = c->nk_read(c, c->rbuf + c->rbytes, avail);
#else
        res = c->read(c, c->rbuf + c->rbytes, avail);
#endif
        if (res > 0) {
            gotdata = READ_DATA_RECEIVED;
            c->rbytes += res;
            //printf("read %d bytes avail %d rbytes %d rsize %d\n", res, avail, c->rbytes, c->rsize);
            if (res == avail) {
                continue;
            } else {
                break;
            }
        }
        if (res == 0) { 
            return READ_ERROR;
        }
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return READ_ERROR;
        }
    }
    return gotdata;
}

enum store_item_type do_store_item(item *it, int comm, conn *c, const uint32_t hv) {
    char *key = ITEM_key(it);
    item *old_it = do_item_get(key, it->nkey, hv, c, DONT_UPDATE);
    enum store_item_type stored = NOT_STORED;

    item *new_it = NULL;
    uint32_t flags;

    if (comm == NREAD_CAS) {
        /* validate cas operation */
        if (old_it == NULL) {
            stored = NOT_FOUND;
        } else if (ITEM_get_cas(it) == ITEM_get_cas(old_it)) {
            // cas validates  
            item_replace(old_it, it, hv);
            stored = STORED;
        } else if (c->set_stale && ITEM_get_cas(it) < ITEM_get_cas(old_it)) {
            // if we're allowed to set a stale value, CAS must be lower than
            // the current item's CAS.
            // This replaces the value, but should preserve TTL, and stale
            // item marker bit + token sent if exists.
            it->exptime = old_it->exptime;
            it->it_flags |= ITEM_STALE;
            if (old_it->it_flags & ITEM_TOKEN_SENT) {
                it->it_flags |= ITEM_TOKEN_SENT;
            }
            item_replace(old_it, it, hv);
            stored = STORED;
        } else {
            stored = EXISTS;
        }
    } else {
        if (old_it != NULL) {
            STORAGE_delete(c->thread->storage, old_it);
            item_replace(old_it, it, hv);
        } else {
            do_item_link(it, hv);
        }
        c->cas = ITEM_get_cas(it);
        stored = STORED;
    }

    if (old_it != NULL)
        do_item_remove(old_it);         /* release our reference */
    if (new_it != NULL)
        do_item_remove(new_it);

    if (stored == STORED) {
        c->cas = ITEM_get_cas(it);
    }

    return stored;
}

static void* binary_get_key(conn* c) {
    return c->rcurr + sizeof(c->binary_header) + c->binary_header.request.extlen;
}

static void* binary_get_request(conn* c) {
    return c->rcurr; 
}

static int process_bin_set(conn *c) {
    int ret = 0;
    item *it;

    protocol_binary_request_set* req = binary_get_request(c);
    char* key = binary_get_key(c);
    int nkey = c->binary_header.request.keylen;

    /* fix byteorder in the request */
    req->message.body.flags = ntohl(req->message.body.flags);
    req->message.body.expiration = ntohl(req->message.body.expiration);

    // bodylen = key + value
    int vlen = c->binary_header.request.bodylen - (nkey + c->binary_header.request.extlen);

    if (settings.verbose > 1) {
        int ii;
        if (c->cmd == PROTOCOL_BINARY_CMD_SET) {
            fprintf(stderr, "<%d SET ", c->sfd);
        } else {
            fprintf(stderr, "<%d UNHANDLED ", c->sfd);
        }
        for (ii = 0; ii < nkey; ++ii) {
            fprintf(stderr, "%c", key[ii]);
        }

        fprintf(stderr, " Value len is %d", vlen);
        fprintf(stderr, "\n");
    }

    it = item_alloc(key, nkey, req->message.body.flags,
            realtime(req->message.body.expiration), vlen+2);

    if(it == NULL) {
        if (! item_size_ok(nkey, req->message.body.flags, vlen + 2)) {
            printf("TOO_LARGE: nkey %d vlen+2 %d\n", nkey, vlen+2);
        } else {
            printf("OUT_OF_MEMORY: nkey %d vlen+2 %d\n", nkey, vlen+2);
        }

        return 0; // TODO return value
    }

    ITEM_set_cas(it, c->binary_header.request.cas);

    switch (c->cmd) {
        case PROTOCOL_BINARY_CMD_SET:
            c->cmd = NREAD_SET;
            break;
        default:
            printf("Receive unhandled cmd %d\n", c->cmd);
            assert(0);
    }

    if (ITEM_get_cas(it) != 0) {
        c->cmd = NREAD_CAS;
    }

    c->item = it;

    // now handle the value part
    protocol_binary_response_status eno = PROTOCOL_BINARY_RESPONSE_EINVAL;

    if ((it->it_flags & ITEM_CHUNKED) == 0) {
        *(ITEM_data(it) + it->nbytes - 2) = '\r';
        *(ITEM_data(it) + it->nbytes - 1) = '\n';
    } else {
        assert(c->ritem);
        item_chunk *ch = (item_chunk *) c->ritem;
        if (ch->size == ch->used)
            ch = ch->next;
        assert(ch->size - ch->used >= 2);
        ch->data[ch->used] = '\r';
        ch->data[ch->used + 1] = '\n';
        ch->used += 2;
    }

    enum store_item_type res = store_item(it, c->cmd, c);
    //printf("store item for cmd %d return %d\n", c->cmd, ret);

    switch (res) {
        case STORED:
            ret =write_bin_response(c, NULL, 0, 0, 0);
            break;
        case EXISTS:
            ret =write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, NULL, 0);
            break;
        case NOT_FOUND:
            ret = write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
            break;
        case NOT_STORED:
        case TOO_LARGE:
        case NO_MEMORY:
            ret = write_bin_error(c, PROTOCOL_BINARY_RESPONSE_NOT_STORED, NULL, 0);
            break;
    }

    item_remove(c->item); 
    c->item = 0;

    return ret;
}

static int process_bin_get(conn *c) {
    item *it;

    protocol_binary_response_get* rsp = (protocol_binary_response_get*)c->wbuf;
    char* key = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;

    if (settings.verbose > 1) {
        fprintf(stderr, "<%d GET ", c->sfd); 
#ifdef __Nautilus__
        for (int ii = 0; ii < nkey; ++ii) {
            fprintf(stderr, "%c", key[ii]);
        }
        fprintf(stderr, "\n");
#else
        if (fwrite(key, 1, nkey, stderr)) {}
        fputc('\n', stderr);
#endif
    }

    it = item_get(key, nkey, c, DO_UPDATE);

    if(it) {
        uint16_t keylen = 0;
        uint32_t bodylen = sizeof(rsp->message.body) + (it->nbytes - 2);

        add_bin_header(c, 0, sizeof(rsp->message.body), keylen, bodylen);
        rsp->message.header.response.cas = htonll(ITEM_get_cas(it));
        // add the flags
        FLAGS_CONV(it, rsp->message.body.flags);
        rsp->message.body.flags = htonl(rsp->message.body.flags);
        add_iov(c, &rsp->message.body, sizeof(rsp->message.body));

        if ((it->it_flags & ITEM_CHUNKED) == 0) {
            add_iov(c, ITEM_data(it), it->nbytes - 2);
        } else {
            add_chunked_item_iovs(c, it, it->nbytes - 2);
        }

        //conn_set_state(c, conn_mwrite);
        //printf("item get ok %p for cmd %d\n", it, c->cmd);
        return handle_conn_mwrite(c);
    } else {
        //printf("item get NULL for cmd %d\n", c->cmd);
        write_bin_miss_response(c, NULL, 0);
    }

    return 0;
}

// https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped
static int process_cmd_binary(conn *c) {
    int ret = 0;

#if 0
    if(settings.verbose > 2) {
        protocol_binary_request_header* req = (protocol_binary_request_header*)rcurr;
        int ii;
        fprintf(stderr, "<%d Read binary protocol data:", c->sfd);
        for (ii = 0; ii < sizeof(req->bytes); ++ii) {
            if (ii % 4 == 0) {
                fprintf(stderr, "\n<%d   ", c->sfd);
            }
            fprintf(stderr, " 0x%02x", req->bytes[ii]);
        }
        fprintf(stderr, "\n");
        //req = (protocol_binary_request_header*)((char*)req + ntohl(req->request.bodylen) + 24); 
    }
#endif
    //char* rend = c->rbuf + c->rbytes;
    //while(c->rcurr < rend) {
    while(c->rbytes > sizeof(c->binary_header)) {

        protocol_binary_request_header* req = (protocol_binary_request_header*)c->rcurr;
#if 1
        if(settings.verbose > 2) {
            int ii;
            fprintf(stderr, "<%d Read binary protocol data:", c->sfd);
            for (ii = 0; ii < sizeof(req->bytes); ++ii) {
                if (ii % 4 == 0) {
                    fprintf(stderr, "\n<%d   ", c->sfd);
                }
                fprintf(stderr, " 0x%02x", req->bytes[ii]);
            }
            fprintf(stderr, "\n");
            //req = (protocol_binary_request_header*)((char*)req + ntohl(req->request.bodylen) + 24); 
        }
#endif
        c->binary_header = *req;
        c->binary_header.request.keylen = ntohs(req->request.keylen);
        c->binary_header.request.bodylen = ntohl(req->request.bodylen);
        c->binary_header.request.cas = ntohll(req->request.cas);

        //fprintf(stderr, "keylen %d bodylen %d\n", c->binary_header.request.keylen, c->binary_header.request.bodylen);

        if(c->rbytes < c->binary_header.request.bodylen + sizeof(c->binary_header)) {
            //fprintf(stderr, "rbytes %d current cmd body %dB header %luB\n",
                //c->rbytes, c->binary_header.request.bodylen, sizeof(c->binary_header));
            // it may not be an error, wait for future data
            return 0;
            //return -1;
        }

        if (c->binary_header.request.magic != PROTOCOL_BINARY_REQ) {
            printf("Receive magic %x, expecting %x\n", c->binary_header.request.magic, PROTOCOL_BINARY_REQ);
            return -1;
        }

        c->msgcurr = 0;
        c->msgused = 0;
        c->iovused = 0;
        // zjp this add_msghdr() seems redundant
        if (add_msghdr(c) != 0) {
            fprintf(stderr, "SERVER_ERROR Out of memory allocating headers\n");
            return -1;
        }

        c->cmd = c->binary_header.request.opcode;
        c->keylen = c->binary_header.request.keylen;
        c->opaque = c->binary_header.request.opaque;
        /* clear the returned cas value */
        c->cas = 0;

        switch(c->cmd) {
            case PROTOCOL_BINARY_CMD_SETQ:
                c->cmd = PROTOCOL_BINARY_CMD_SET;
                break;
            case PROTOCOL_BINARY_CMD_GETQ:
                c->cmd = PROTOCOL_BINARY_CMD_GET;
                break;
            default:
                //c->noreply = false;
                break;
        }
        //printf("Receive cmd %d\n", c->cmd);

        // now we have received a SET or GET
        //c->ritem = c->rbuf + sizeof(protocol_binary_request_header);

        switch(c->cmd) {
            case PROTOCOL_BINARY_CMD_SET:
                ret = process_bin_set(c);
                break;
            case PROTOCOL_BINARY_CMD_GET:
                ret = process_bin_get(c);
                break;
            default:
                printf("Receive unhandled cmd %d\n", c->cmd);
                return -1;
        }

        if(ret != 0) { // as long as one cmd is invalid, we directly return
            printf("process bin cmd %d failed\n", c->cmd);
            return ret;
        }

        // proceed to next cmd
        int offset = ntohl(req->request.bodylen) + 24;
        c->rcurr += offset; 
        c->rbytes -= offset; 
    }
    //printf(" rcurr %p rend %p\n", c->rcurr, rend);
    return ret;
}

static void conn_shrink(conn *c) {
    // Don't shrink, we want to test large memory consumption
}

static void reset_cmd_handler(conn *c) {
    c->cmd = -1;
    if(c->item != NULL) {
        item_remove(c->item);
        c->item = NULL;
    }
    conn_shrink(c);
    /*
    if (c->rbytes > 0) {
        conn_set_state(c, conn_parse_cmd);
    } else {
        conn_set_state(c, conn_waiting);
    }
    */
}

void drive_machine(conn *c) {
    while (1) { // conn loop
        /* don't switch to other conn
        if(--nreqs <= 0) {
            break;
        }
        */
        int res = try_read_network(c);
        if(res == READ_NO_DATA_RECEIVED) {
            continue; // keep working on this conn
        } else if(res == READ_DATA_RECEIVED) {
            // now all data is in c->rbuf
            //printf("READ_DATA_RECEIVED\n");
            if(0 == process_cmd_binary(c)) {
                // now cmd is processed correctly
                //printf("process_cmd_binary succeeded\n");
            } else {
                fprintf(stderr, "process_cmd_binary failed\n");
            }
            // reset before next cmd
            reset_cmd_handler(c); 
            continue;
        } else { // done with this conn
            printf("Close connection %p socket %d\n", c, c->sfd);
            conn_close(c);
            break;
        }
    } // conn loop
}

#ifdef __Nautilus__
static int
handle_memcached(char * buf, void * priv) {
#else
int main() {
#endif
    
    settings.verbose = 2;//2;
    settings.maxconns = 1024;

    settings.port = 11211;
    settings.num_threads = 4;
    settings.maxbytes = 64 * 1024 * 1024;
    settings.oldest_live = 0;
    settings.oldest_cas = 0;
    settings.factor = 1.25;
    settings.chunk_size = 48;
    settings.hashpower_init = 0;
    settings.item_size_max = 1024 * 1024;
    settings.slab_page_size = 1024 * 1024;
    settings.slab_chunk_size_max = settings.slab_page_size / 2;
    settings.use_cas = true;

    // from NO_MODERN
    settings.slab_chunk_size_max = settings.slab_page_size;

    enum hashfunc_type hash_type = MURMUR3_HASH;

    process_started = time(0) - ITEM_UPDATE_INTERVAL - 2;

    if (hash_init(hash_type) != 0) {
        fprintf(stderr, "Failed to initialize hash_algorithm!\n");
        return -1;
    }

    conn_init();

    assoc_init(settings.hashpower_init);

    /* slab init */
    bool preallocate = false;
    bool reuse_mem = false;
    void* mem_base = NULL;
    slabs_init(settings.maxbytes, settings.factor, preallocate,
                NULL, mem_base, reuse_mem);

    /* threads init */
    memcached_thread_init(settings.num_threads, NULL);

    /* lru crawler */
    //init_lru_crawler(NULL);

    /* maintainer threads */
#if 0
    if (start_assoc_maint && start_assoc_maintenance_thread() == -1) {
        exit(EXIT_FAILURE);
    }
    if (start_lru_crawler && start_item_crawler_thread() != 0) {
        fprintf(stderr, "Failed to enable LRU crawler thread\n");
        exit(EXIT_FAILURE);
    }
    if (start_lru_maintainer && start_lru_maintainer_thread(NULL) != 0) {
        fprintf(stderr, "Failed to enable LRU maintainer thread\n");
        return 1;
    }
#endif
    /* no re-assign */

    /* no idle-timeout */

    /* use tcp */
    int acc_sock;
    if ((acc_sock = server_socket(settings.port)) == -1 ) {
        printf("failed to listen on TCP port %d\n", settings.port);
        return 0;
    }

    /* Initialize the uriencode lookup table. */
    uriencode_init();

    /* main loop */
    while (!stop_main_loop) {
        int conn_sock;
        struct sockaddr_in client_addr; 
        socklen_t client_addrlen = sizeof(client_addr);
        printf("Waiting for clients\n");
        conn_sock = accept(acc_sock, (struct sockaddr*)&client_addr, &client_addrlen);
        if(conn_sock >= 0) {
            printf("new conn %d arrives\n", conn_sock); 
            dispatch_conn_new(conn_sock, DATA_BUFFER_SIZE);
        }
    }

    if(acc_sock >= 0)
        close(acc_sock);

    /* clearance */
    //stop_threads();
    //conn_close();

    return 0;
}
#ifdef __Nautilus__
static struct shell_cmd_impl memcached_impl = {
    .cmd      = "memcached",
    .help_str = "memcached", 
    .handler  = handle_memcached,
};
nk_register_shell_cmd(memcached_impl);
#endif
