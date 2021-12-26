#include <future>
#include <thread>
#include <chrono>
#include <vector>
#include <queue>
#include "aes_encrypt_decrypt.hpp"
#include "ceSerial.h"
#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/ecp.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
#include "cryptopp/sha3.h"
#include "cryptopp/hmac.h"
#include "TCPClient.hpp"


using namespace std;
using namespace ce;
namespace ASN1 = CryptoPP::ASN1;
using namespace CryptoPP;
typedef DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;

string THIS_NODE_NAME = "G1";
const string SEPARATION = "|";
const string ECC_DH = "0";
const string FORWARD_TO_NODE = "1";
const string FORWARD_TO_EDGE = "2";
const string SEND_DATA = "3";
const string CONNECT = "4";
const string EDGE_SEND_GROUP = "5";
const string ACCEPT = "6";

bool SendFrame(ceSerial& com, string message);
string ReceiveFrame(ceSerial& com, bool& successFlag);
string PointToString(ECP::Point p);
ECP::Point StringToPoint(string str);
string H(const string& value);
string _HMAC(const string& m, string key);
string ECC_DH_key_exchange();
void ReceiveForeverFromEdge();
void CommunicateWithNode();
string GetGroupKey(string msg, bool use_eu = false);
void Exec();
void Run();


string key_eu = "B53FF2C5354A917EABE5DAF91EC2279A5468D811511B6B72C6B95C4C33D5142F";
string key_b = "E13278C9D9CBD09E4EF8DEA1548CE15D533A3DB5D97BDD2F7069245936ECD7F1";
string key_group = "";
string key_eg = "";
string session_key = "";

bool run = false;
string server_ip = "";
uint16_t port = 8080;
string serial_port = "";


queue<string> queue_receive_from_edge;
queue<string> queue_send_to_node;
queue<string> queue_receive_from_node;

int main(int argc, char* argv[]){

	stringstream ss;
	ss << argv[3];
	port = (uint16_t)stoi(ss.str());
	serial_port = argv[1];
	server_ip = argv[2];
	THIS_NODE_NAME = argv[4];

	
	run = true;

	future<void> recv_edge = async(ReceiveForeverFromEdge);
	future<void> comunicate_node = async(CommunicateWithNode);
	future<void> ru = async(Run);


	recv_edge.wait();
	comunicate_node.wait();
	ru.wait();
	return 0;
}

bool SendFrame(ceSerial& com, string message){
	return com.Write(message.c_str());
}

string ReceiveFrame(ceSerial& com, bool& successFlag){
	char temp = 'a';
	string buffer = "";
	do {
		temp = com.ReadChar(successFlag);
		buffer += temp;
		if (temp == '\n') break;
	} while (successFlag);
	return buffer;
}

string PointToString(ECP::Point p){
	stringstream ss, ss1;
	string key = "";
	ss << hex << p.x;
	key += ss.str();
	key += ":";
	ss1 << hex << p.y;
	key += ss1.str();
	return key;
}

ECP::Point StringToPoint(string str){
	vector<string> x_y = StringSplit(str, ":");
	Integer x(x_y[0].c_str());
	Integer y(x_y[1].c_str());
	ECP::Point p(x, y);
	return p;
}

string H(const string& value){
    string digest;
    SHA3_256 hash;
    hash.Update((const byte*)value.data(), value.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    string encoded;
    StringSource(digest, true,
		new HexEncoder(
			new StringSink(encoded)
		)
	);
    return encoded;
}

string _HMAC(const string& m, string key){
	string destination = "";
	StringSource ss(key, true, new HexDecoder(new StringSink(destination)));    
	const byte* bkey = (const byte*) destination.data();
	
	HMAC<SHA3_256> hmac(bkey, key.length()/2);
	
	string mac;
    StringSource ss2(m, true, 
        new HashFilter(hmac,
            new StringSink(mac)
        )       
    );

	string encoded;
    StringSource(mac, true,
		new HexEncoder(
			new StringSink(encoded)
		)
	);
	return encoded;
}

string ECC_DH_key_exchange(){
	CryptoPP::DL_GroupParameters_EC<ECP> curve512;
	curve512.Initialize(ASN1::brainpoolP512r1());

	AutoSeededRandomPool rng;
	Integer x(rng, 256);
	Integer y(rng, 265);
	Integer k(rng, 16);
	ECP::Point G(x, y);

	ECP::Point public_point = curve512.GetCurve().Multiply(k, G);
	string public_key = PointToString(public_point);

	TCPClient client;

	client.Connect(server_ip, port);
	string msg = ECC_DH + SEPARATION + THIS_NODE_NAME + SEPARATION + public_key + SEPARATION;
	string tag = _HMAC(msg, key_group);
	msg = msg + tag;
	client.Send(msg);

	string response = client.Receive(1024);
	vector<string> packge = StringSplit(response, SEPARATION);

	if (_HMAC(response.substr(0, (response.length()-packge[3].length())), key_group) != packge[3]){
		cerr << "verify error! _HMAC(response.substr(0, (response.length()-packge[3].length())), key_group) != packge[3]" << endl;
		return "";
	}

	if (packge[0] == ECC_DH && packge[1] == THIS_NODE_NAME){
		ECP::Point public_point_edge = StringToPoint(packge[2]);
		ECP::Point private_point = curve512.GetCurve().Multiply(k, public_point_edge);
		return H(PointToString(private_point));
	}
	else return "";
}

void ReceiveForeverFromEdge(){
	TCPClient client_recv;
	client_recv.Connect(server_ip, port);

	string msg = CONNECT + SEPARATION + THIS_NODE_NAME;
	client_recv.Send(msg);

	string response = "";
	cout << "ReceiveForeverFromEdge()\n";
	while (run)
	{
		response = client_recv.Receive(2048);
		if (response != "") queue_receive_from_edge.push(response);
		this_thread::sleep_for(chrono::milliseconds(10));
	}
	client_recv.Close();
}

void CommunicateWithNode(){
	//ceSerial com("/dev/ttyUSB0",9600,8,'N',1);
	//ceSerial com("\\\\.\\COM7",9600,8,'N',1);
	ceSerial com(serial_port.c_str(),9600,8,'N',1);
	string buffer = "";
	bool successFlag;

	if (com.Open() != 0) return;
	cout << "CommunicateWithNode()\n";

	successFlag = SendFrame(com, CONNECT+SEPARATION+THIS_NODE_NAME+"\n");
	if(!successFlag) {cerr << "CommunicateWithNode() error!\n"; return;}
	com.Delay(1000);

	while (run){

		while (!queue_send_to_node.empty()){

			successFlag = SendFrame(com, queue_send_to_node.front()+"\n");
			if(!successFlag) cerr << "Forward to node error!\n";
			else cout << "Forward to node: OK!\n";
			queue_send_to_node.pop();
			com.Delay(10);
			
		}

		buffer = ReceiveFrame(com, successFlag);
		if (successFlag && buffer != ""){
			buffer = buffer.substr(0, buffer.length()-1);
			if (buffer != "") queue_receive_from_node.push(buffer);
		}

		this_thread::sleep_for(chrono::milliseconds(10));

	}
	com.Close();
}

string GetGroupKey(string msg, bool use_eu){
	vector<string> v1 = StringSplit(msg, "|");

	MyAES myaes;
	if (use_eu) {
		myaes.SetKeyFromHexString(key_eu);
		string rs = myaes.Decryption(v1[v1.size()-1]);
		vector<string> vrs = StringSplit(rs, "|");
	
		key_eg = vrs[2];
		return vrs[1];
	}
	else {
		myaes.SetKeyFromHexString(key_group);
		string rs = myaes.Decryption(v1[v1.size()-1]);
		vector<string> vrs = StringSplit(rs, "|");
	
		if (H(vrs[0]) == key_eg) {
			key_eg = vrs[0];
		
			string t1 = key_eg + "h", t2 = key_b + "h";
			Integer a(t1.c_str()), b(t2.c_str());
			Integer c = a.Or(b);

			stringstream ss;
			ss << hex << c;
			return H(ss.str().substr(0, ss.str().length()-1));
		}

		return key_group;
	}

}

void Exec(const string& _case, string msg){
	
	if (_case == ACCEPT){
		queue_send_to_node.push(msg);
		key_group = GetGroupKey(msg, true);
	}
	else if (_case == EDGE_SEND_GROUP){
		queue_send_to_node.push(msg);
		key_group = GetGroupKey(msg);
	}
	else if (_case == FORWARD_TO_NODE){
		queue_send_to_node.push(msg);
	}
	else if (_case == SEND_DATA){
		session_key = ECC_DH_key_exchange();

		TCPClient client;
		client.Connect(server_ip, port);
		client.Send(msg);
		client.Close();
	}
	else if (_case == FORWARD_TO_EDGE){
		msg += (SEPARATION + THIS_NODE_NAME);
		TCPClient client;
		client.Connect(server_ip, port);
		client.Send(msg);
		client.Close();
	}
	
}

void Run(){

	int loop = 0;
	string msg = "";
	MyAES myaes;

	while (run)
	{
		while (!queue_receive_from_edge.empty()){
			Exec(queue_receive_from_edge.front().substr(0, 1), 
				queue_receive_from_edge.front()
			);
			queue_receive_from_edge.pop();
		}
		while (!queue_receive_from_node.empty()){
			Exec(queue_receive_from_node.front().substr(0, 1), 
				queue_receive_from_node.front()
			);
			queue_receive_from_node.pop();
		}
		this_thread::sleep_for(chrono::milliseconds(10));
		loop++;

		if (loop == 3000) {
			msg = SEND_DATA + SEPARATION + THIS_NODE_NAME + SEPARATION;
			
			if (session_key == "") session_key = ECC_DH_key_exchange();

			myaes.SetKeyFromHexString(session_key);
			msg += myaes.Encryption("hello test");
			msg += SEPARATION;
			msg += _HMAC(msg, key_group);

			TCPClient client;
			client.Connect(server_ip, port);
			client.Send(msg);
			client.Close();

			loop = 0;
		}
	}

	run = false;
}

