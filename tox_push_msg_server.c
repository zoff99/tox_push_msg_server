/**
 *
 * Tox Push Msg Server
 * 
 * (C)Zoff <zoff@zoff.cc> in 2021
 *
 * https://github.com/zoff99/tox_push_msg_server
 *
 *
 */
/*
 * Copyright © 2021 Zoff <zoff@zoff.cc>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */

/*

  # compile on linux:

  gcc -O3 -g -fPIC -Wall -Wextra \
     -fno-omit-frame-pointer \
     -fsanitize=address \
     -fstack-protector-all \
     --param=ssp-buffer-size=1 \
     -Wlarger-than=5000 \
     -Wframe-larger-than=5000 \
     -Wvla \
     -Werror=div-by-zero \
     tox_push_msg_server.c \
     -lcurl \
     -o tox_push_msg_server

 */


#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <signal.h>

#include <curl/curl.h>

#include "fcm_config.h"

#define MAX_HEADER_LENGTH 1000
#define MAX_POSTDATA_LENGTH 2000

int trigger_push(const char *device_token_str);


#define HSTATIC_EPOLL_EVENTS 64
#define HSTATIC_PORT 8787
#define HSTATIC_TCP_BACKLOG 4
#define HSTATIC_TCP_MAX_INPUT_BYTES 4096

typedef enum connection_type {
	CONNECTION_TYPE_CLIENT,
	CONNECTION_TYPE_SERVER
} connection_type_e;

/**
 * Encapsulates the properties of a connection.
 */
typedef struct connection {
	// file descriptor of the socket that connected
	// to our server after being `accept`ed.
	int fd;

	// type of the connection represented
	connection_type_e type;
} connection_t;

typedef int (*connection_handler)(connection_t*);


typedef struct server {
	// epoll_fd is the epoll file descriptor retrieved from
	// an `epoll_create` op.
	int epoll_fd;

	// server connection that holds the underlying passive
	// socket where connections get accepted from.
	connection_t* conn;

	// callback to execute whenever a new connection
	// is accepted.
	connection_handler connection_handler;
} server_t;

server_t* server = NULL;


/* TCP stuff */

connection_t*
connection_create(connection_type_e type)
{
	connection_t* conn = malloc(sizeof(*conn));

	if (conn == NULL) {
		perror("malloc");
		printf("failed to allocate memory for connection\n");
		return conn;
	}

	conn->type = type;
	conn->fd   = -1;

	return conn;
}

int
connection_destroy(connection_t* conn)
{
	int err;

	if (conn == NULL) {
		return 0;
	}

	if (conn->fd != -1) {
		err = close(conn->fd);
		if (err == -1) {
			perror("close");
			printf("failed to close connection file descriptor\n");
			return -1;
		}
	}

	return 0;
}

int
fd_make_nonblocking(int socket)
{
	int err = 0;
	int flags;

	err = (flags = fcntl(socket, F_GETFL, 0));
	if (err == -1) {
		perror("fcntl");
		printf("failed to retrieve socket flags\n");
		return -1;
	}

	flags |= O_NONBLOCK;

	err = fcntl(socket, F_SETFL, flags);
	if (err == -1) {
		perror("fcntl");
		printf("failed to set socket flags\n");
		return -1;
	}

	return 0;
}


server_t*
server_create(connection_handler handler)
{
	server_t*     server;
	connection_t* conn;

	if (handler == NULL) {
		printf("handler must be specified\n");
		return NULL;
	}

	conn = connection_create(CONNECTION_TYPE_SERVER);
	if (conn == NULL) {
		printf("failed to create server connection\n");
		return NULL;
	}

	server = malloc(sizeof(*server));
	if (server == NULL) {
		perror("malloc");
		printf("failed to allocate memory for server struct\n");
		return NULL;
	}

	server->epoll_fd           = -1;
	server->conn               = conn;
	server->connection_handler = handler;

	return server;
}

int
server_destroy(server_t* server)
{
	int err = 0;

	if (server->conn != NULL) {
		err = connection_destroy(server->conn);
		if (err) {
			printf("failed to destroy server connection\n");
			return err;
		}

		free(server->conn);

		server->conn = NULL;
	}

	if (server->epoll_fd != -1) {
		err = close(server->epoll_fd);
		if (err == -1) {
			perror("close");
			printf("failed to close server epoll fd\n");
			return err;
		}

		server->epoll_fd = -1;
	}

	return 0;
}


/**
 * Accepts all incoming established TCP connections
 * until a blocking `accept(2)` would occur.
 */
int
_accept_all(server_t* server)
{
	struct sockaddr    in_addr;
	struct epoll_event event  = { 0 };
	socklen_t          in_len = sizeof in_addr;
	connection_t*      conn;
	int                in_fd;
	int                err;

	while (1) {
		in_fd = accept(server->conn->fd, &in_addr, &in_len);
		if (in_fd == -1) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				return 0;
			}

			perror("accept");
			printf("failed unexpectedly while accepting "
			       "connection");
			return -1;
		}

		// Make the incoming socket non-blocking
		fd_make_nonblocking(in_fd);

		conn = connection_create(CONNECTION_TYPE_CLIENT);
		if (conn == NULL) {
			printf("failed to create connection struct\n");
			return -1;
		}

		conn->fd = in_fd;

		event.data.ptr = conn;
		event.events   = EPOLLIN | EPOLLET;

		// add the non-blocking socket to the epoll set
		err = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, in_fd, &event);
		if (err == -1) {
			perror("epoll_ctl");
			printf("couldn't add client socket to epoll set\n");
			return -1;
		}
	}

	return 0;
}

int
server_serve(server_t* server)
{
	int epoll_fd;
	int err = 0;

	struct epoll_event event = { 0 };
	struct epoll_event events[HSTATIC_EPOLL_EVENTS];

	// creates a new epoll instance and returns a file
	// descriptor referring to that instance.
	err = (epoll_fd = epoll_create1(0));
	if (err == -1) {
		perror("epoll_create1");
		printf("couldn't create epoll fd\n");
		return err;
	}

	server->epoll_fd = epoll_fd;

	// Interest in particular file descriptors is then
	// registered via epoll_ctl(2) - adds the file descriptor to
	// the epoll set.
	//
	// Here we register the target file descriptor server->listen_fd
	// on the epoll instance referred to by the file descriptor
	// epoll_fd and associate the event `event` with the internal file
	// linked to epoll_fd.
	event.data.ptr = server->conn;
	event.events   = EPOLLIN | EPOLLET;

	err =
	  epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->conn->fd, &event);
	if (err == -1) {
		perror("epoll_ctl");
		printf("failed to add listen socket to epoll event");
		return err;
	}

	for (;;) {
		// Wait indefintely (-1) until there's a file descriptor ready
		// to proceed with IO in a non-blocking manner.
		//
		// When at least one file descriptor is ready, we'll receive in
		// `fds_len` the number of file descriptors ready.
		//
		// `events` array gets populated with the events, which allows
		// us
		// to retrieve these events by simply looping over the array.
		int fds_len = epoll_wait(
		  server->epoll_fd, events, HSTATIC_EPOLL_EVENTS, -1);
		if (fds_len == -1) {
			if (errno == EINTR) {
				return 0;
			}

			perror("epoll_wait");
			printf("failed to wait for epoll events");
			return -1;
		}

        int i = 0;
		for (i = 0; i < fds_len; i++) {
			connection_t* event_conn = events[i].data.ptr;

			// Check the case where either:
			// - an error occurred
			// - we received a hangup from the other side
			// - the event is not for reading from a socket or
			// accepting
			//   connections.
			if ((events[i].events & EPOLLERR) ||
			    (events[i].events & EPOLLHUP) ||
			    (!(events[i].events & EPOLLIN))) {
				err = connection_destroy(event_conn);
				if (err) {
					printf(
					  "failed to destroy connection\n");
					return -1;
				}

				free(events[i].data.ptr);
				continue;
			}

			// If we're getting a notification of IO ready in our
			// server listener fd, then that means we have at least
			// one new connection waiting to be accepted.
			//
			// To make sure we accept them all, try to accept as
			// much
			// as we can until an EAGAIN or EWOULDBLOCK is reached.
			if (event_conn->type == CONNECTION_TYPE_SERVER) {
				err = _accept_all(server);
				if (err) {
					printf("failed to accept "
					       "connection\n");
					return err;
				}

				continue;
			}

			// TODO handle possible errors?
			server->connection_handler(events[i].data.ptr);
		}
	}

	return 0;
}


int
server_listen(server_t* server)
{
	int                err         = 0;
	struct sockaddr_in server_addr = { 0 };

	// `sockaddr_in` provides ways of representing a full address
	// composed of an IP address and a port.
	//
	// SIN_FAMILY   address family          AF_INET refers to the
	//                                      address family related to
	//                                      internet addresses
	//
	// S_ADDR       address (ip) in network byte order (big endian)
	// SIN_PORT     port in network byte order (big endian)
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port        = htons(HSTATIC_PORT);

	// The `socket(2)` syscall creates an endpoint for communication
	// and returns a file descriptor that refers to that endpoint.
	//
	// It takes three arguments (the last being just to provide
	// greater specificity):
	// -    domain (communication domain)
	//      AF_INET              IPv4 Internet protocols
	//
	// -    type (communication semantics)
	//      SOCK_STREAM          Provides sequenced, reliable,
	//                           two-way, connection-based byte
	//                           streams.
	err = (server->conn->fd = socket(AF_INET, SOCK_STREAM, 0));
	if (err == -1) {
		perror("socket");
		printf("Failed to create socket endpoint\n");
		return err;
	}

	// bind() assigns the address specified to the socket referred
	// to by the file descriptor (`listen_fd`).
	//
	// Here we cast `sockaddr_in` to `sockaddr` and specify the
	// length such that `bind` can pick the values from the
	// right offsets when interpreting the structure pointed to.
	err = bind(server->conn->fd,
	           (struct sockaddr*)&server_addr,
	           sizeof(server_addr));
	if (err == -1) {
		perror("bind");
		printf("Failed to bind socket to address\n");
		return err;
	}

	// Makes the server socket non-blocking such that calls that
	// would block return a -1 with EAGAIN or EWOULDBLOCK and
	// return immediately.
	err = fd_make_nonblocking(server->conn->fd);
	if (err) {
		printf("failed to make server socket nonblocking\n");
		return err;
	}

	// listen() marks the socket referred to by sockfd as a
	// passive socket, that is, as a socket that will be used to accept
	// incoming connection requests using accept(2).
	err = listen(server->conn->fd, HSTATIC_TCP_BACKLOG);
	if (err == -1) {
		perror("listen");
		printf("Failed to put socket in passive mode\n");
		return err;
	}

	return 0;
}

static const char* tcp_response = "OK\r\n";
static const size_t tcp_response_len = 4;

int
tcp_handler(connection_t* conn)
{
	int  n = 0;
	char buf[HSTATIC_TCP_MAX_INPUT_BYTES + 1];
    memset(buf, 0, HSTATIC_TCP_MAX_INPUT_BYTES + 1);

	//for (int jj=0;jj<4;jj++) {
		n = read(conn->fd, buf, HSTATIC_TCP_MAX_INPUT_BYTES);
		if (n == -1) {
			//if (errno == EAGAIN || errno == EWOULDBLOCK) {
			//	//break;
			//}

			perror("read");
			printf("failed to read from the client\n");
			return -1;
		}

		//if (n == 0) {
		//	break;
		//}
	//}

    // do our FCM push triggering here --------------------
    if ((n > 20) && (n < HSTATIC_TCP_MAX_INPUT_BYTES))
    {
        // fprintf(stderr, "buf=%s\n", buf);
        int res = trigger_push(buf);
        if (res) {}
        // fprintf(stderr, "res=%d\n", res);
    }

    // do our FCM push triggering here --------------------

	n = write(conn->fd, tcp_response, tcp_response_len);
	if (n == -1) {
		perror("write");
		printf("failed to write to client\n");
		return -1;
	}

	return 0;
}

void
sig_handler(int signo __attribute__((unused)))
{
	int err;

	if (server == NULL) {
		exit(0);
	}

	err = server_destroy(server);
	if (err) {
		printf("errored while gracefully destroying server\n");
		exit(err);
	}
}

/*  GCM stuff   */

struct string {
    char *ptr;
    size_t len;
};

void init_string(struct string *s)
{
    s->len = 0;
    s->ptr = calloc(1, s->len + 1);

    if (s->ptr == NULL)
    {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }

    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);

    if (s->ptr == NULL)
    {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }

    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}

int trigger_push(const char *device_token_str)
{
    CURL *curl = NULL;
    CURLcode res;
    char post_data[MAX_POSTDATA_LENGTH];
    char h1[MAX_HEADER_LENGTH];
    int result = 1;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if (curl)
    {
        struct string s;
        init_string(&s);

        curl_easy_setopt(curl, CURLOPT_URL, FCM__dest_url);
        
        memset(post_data, 0, MAX_POSTDATA_LENGTH);
        
        snprintf(post_data, (MAX_POSTDATA_LENGTH - 1),
            "{ \"data\": { \"title\": \"_\", \"body\": \"_\" }, \"to\": \"%s\" }",
            device_token_str);
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        struct curl_slist *list = NULL;

        memset(h1, 0, MAX_HEADER_LENGTH);
        snprintf(h1, (MAX_HEADER_LENGTH - 1), "Authorization:key=%s", FCM__server_key);

        list = curl_slist_append(list, h1);
        list = curl_slist_append(list, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);

        curl_slist_free_all(list);

        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            char *found = strstr((const char *)s.ptr, (const char *)"\"success\":1");

            if (found == NULL)
            {
                fprintf(stderr, "server_answer=%s\n", s.ptr);
            }
            else
            {
                result = 0;
            }
            free(s.ptr);
            s.ptr = NULL;
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return result;
}


/*  MAIN   */

int main(void)
{
    int err = 0;

	if ((signal(SIGINT, sig_handler) == SIG_ERR) || (signal(SIGTERM, sig_handler) == SIG_ERR))
    {
		perror("signal");
		printf("failed to install termination signal handler\n");
		return 1;
	}

    server = server_create(&tcp_handler);
	if (server == NULL)
    {
		printf("failed to instantiate server\n");
		return 1;
	}

	err = server_listen(server);
	if (err)
    {
		printf("Failed to listen on address: 8080\n");
		return err;
	}

	err = server_serve(server);
	if (err)
    {
		printf("Failed serving\n");
		return err;
	}

	err = server_destroy(server);
	if (err)
    {
		printf("failed to destroy server\n");
		return 1;
	}

	free(server);
	server = NULL;

    return 0;
}


