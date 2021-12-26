#ifndef TCPCLIENT_H_
#define TCPCLIENT_H_

#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>

using namespace std;

class TCPClient {
    private:
    int sock, valread;
	struct sockaddr_in serv_addr;

    public:
    TCPClient();
    TCPClient(const TCPClient& client);
    TCPClient(const int& sock_c);

    void Connect(string server_ip, uint16_t server_port);
    string Receive(const size_t& n_bytes);
    void Send(string payload);
    void Close();

    int GetValRead();
    void SetValRead(const int& val);
    int GetSock();

    TCPClient operator=(const TCPClient& client);
    TCPClient operator=(const int& sock_c);
};

#endif