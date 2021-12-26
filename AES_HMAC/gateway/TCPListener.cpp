#include "TCPListener.hpp"

TCPListener::TCPListener(){
    opt = 1;
    addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	    cerr << "socket failed\n";
    
}


void TCPListener::Bind(uint16_t port){
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
												&opt, sizeof(opt)))
		cerr << "setsockopt\n";
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);
	
    if (bind(server_fd, (struct sockaddr *)&address,
								sizeof(address))<0)
		cerr << "bind failed\n";
}

void TCPListener::Listen(uint32_t queue_size){
	if (listen(server_fd, queue_size) < 0)
		cerr << "listen\n";
}

TCPClient TCPListener::Accept(){
	if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
					(socklen_t*)&addrlen))<0)
		cerr << "accept\n";
	return new_socket;
}

string TCPListener::ReceiveFrom(TCPClient& client, const size_t& n_bytes){
	char* buffer = new char[n_bytes];
	valread = read(client.GetSock() , buffer, n_bytes);
	client.SetValRead(valread);
	string s_bufer = buffer;
	delete[] buffer;
	return s_bufer;
}

void TCPListener::SendTo(TCPClient& client, string payload){
	send(client.GetSock(), payload.c_str(),payload.length(), 0 );
}

void TCPListener::Close(){
	close(server_fd);
}