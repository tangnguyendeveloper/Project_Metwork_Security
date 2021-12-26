#ifndef TCPLISTENER_H_
#define TCPLISTENER_H_

#include <unistd.h>
#include <iostream>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string>
#include "TCPClient.hpp"

using namespace std;

class TCPListener {
    private:
    int server_fd, new_socket, valread;
	struct sockaddr_in address;
	int opt;
	int addrlen;

    public:
    TCPListener();

    void Listen(uint32_t queue_size);
    void Bind(uint16_t port);
    TCPClient Accept();
    void SendTo(TCPClient& client, string payload);
    string ReceiveFrom(TCPClient& client, const size_t& n_bytes);
    void Close();
};

#endif