#include "TCPClient.hpp"

TCPClient::TCPClient(){
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		cerr << "\n Socket creation error \n";
	}
}

TCPClient::TCPClient(const TCPClient& client){
    sock = client.sock;
}

TCPClient::TCPClient(const int& sock_c){
    sock = sock_c;
}

void TCPClient::Connect(string server_ip, uint16_t server_port){
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
    if(inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr)<=0)
		cerr << "\nInvalid address/ Address not supported \n";
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		cerr << "\nConnection Failed \n";
}

void TCPClient::Send(string payload){
    send(sock, payload.c_str(), payload.length(), 0 );
}

string TCPClient::Receive(const size_t& n_bytes){
    char* buffer = new char[n_bytes];
    valread = read( sock , buffer, n_bytes);
    string s_buffer = buffer;
    delete[] buffer;
    return s_buffer;
}

void TCPClient::Close(){
    close(sock);
}

int TCPClient::GetValRead(){
    return valread;
}

void TCPClient::SetValRead(const int& val){
    valread = val;
}

int TCPClient::GetSock(){
    return sock;
}

TCPClient TCPClient::operator=(const TCPClient& client){
    return TCPClient(client);
}

TCPClient TCPClient::operator=(const int& sock_c){
    return TCPClient(sock_c);
}