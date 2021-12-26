#include <future>
#include <thread>
#include <chrono>
#include <vector>
#include <queue>
#include <stack>
#include "aes_encrypt_decrypt.hpp"
#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/ecp.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
#include "cryptopp/sha3.h"
#include "cryptopp/hmac.h"
#include "TCPListener.hpp"


using namespace std;
namespace ASN1 = CryptoPP::ASN1;
using namespace CryptoPP;
typedef DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;

string THIS_NODE_NAME = "EDGE";
const string SEPARATION = "|";
const string ECC_DH = "0";
const string FORWARD_TO_NODE = "1";
const string FORWARD_TO_EDGE = "2";
const string SEND_DATA = "3";
const string CONNECT = "4";
const string EDGE_SEND_GROUP = "5";
const string ACCEPT = "6";



void CreateChain();

string PointToString(ECP::Point p);
ECP::Point StringToPoint(string str);
string H(const string& value);
string _HMAC(const string& m, string key);
void ECC_DH_key_exchange(TCPClient client, string msg);
void ReceiveForeverFromGateway();
void GetGroupKey(string group);
void Exec(TCPClient client);
void Run();


string key_eu1 = "B53FF2C5354A917EABE5DAF91EC2279A5468D811511B6B72C6B95C4C33D5142F";
string key_eu2 = "A53FF2C5354A917EABE5DAF91EC2279A5468D811511B6B72C6B95C4C33D5142F";
string key_a = "A63288C9DACBD09E5AF8DEA1548C115D533A3DB5D97BAD2E4069D65936ECD7C9";
string key_b = "E13278C9D9CBD09E4EF8DEA1548CE15D533A3DB5D97BDD2F7069245936ECD7F1";
string key_group1 = "";
string key_group2 = "";
string key_eg = "A53FF2C535CC917EABE5DAF91EC2279A5468D811511B6B72C6B95C4C33D5142F";
string session_key_g1 = "";
string session_key_g2= "";

bool run = false;
uint16_t port = 8080;

stack<string> key_eg_chain;
future<void> client_connect[200];

TCPClient gateway1, gateway2;

int main(int argc, char* argv[]){

	stringstream ss;
	ss << argv[1];
	port = (uint16_t)stoi(ss.str());
	THIS_NODE_NAME = argv[2];

	run = true;

	CreateChain();

	future<void> recv = async(ReceiveForeverFromGateway);
	future<void> ru = async(launch::deferred, Run);

	recv.wait();
	cout << "Please wait 300 seconds for setup...\n";
	this_thread::sleep_for(chrono::seconds(180));
	ru.wait();

	return 0;
}

void CreateChain(){
	for (int i = 0; i < 100; i++){
		key_eg = H(key_eg);
		key_eg_chain.push(key_eg);
	}
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

void ECC_DH_key_exchange(TCPClient client, string msg){

	cout << "ECC_DH_key_exchange\n";

	CryptoPP::DL_GroupParameters_EC<ECP> curve512;
	curve512.Initialize(ASN1::brainpoolP512r1());

	AutoSeededRandomPool rng;
	Integer x(rng, 256);
	Integer y(rng, 265);
	Integer k(rng, 16);
	ECP::Point G(x, y);

	ECP::Point public_point = curve512.GetCurve().Multiply(k, G);
	string public_key = PointToString(public_point);
	string key_group = "";

	vector<string> packge = StringSplit(msg, SEPARATION);
	if (packge[1] == "G1") key_group = key_group1;
	else if (packge[1] == "G2") key_group = key_group2;

	string response = ECC_DH + SEPARATION + THIS_NODE_NAME + SEPARATION + public_key + SEPARATION;
	string tag = _HMAC(response, key_group);
	response = response + tag;
	client.Send(response);

	if (_HMAC(msg.substr(0, (msg.length()-packge[3].length())), key_group) != packge[3]){
		cerr << "verify error! _HMAC(response.substr(0, (response.length()-packge[3].length())), key_group) != packge[3]" << endl;
		return;
	}

	if (packge[0] == ECC_DH && packge[1] == THIS_NODE_NAME){
		ECP::Point public_point_edge = StringToPoint(packge[2]);
		ECP::Point private_point = curve512.GetCurve().Multiply(k, public_point_edge);
		
		if (packge[1] == "G1") session_key_g1 = H(PointToString(private_point));
		else if (packge[1] == "G2") session_key_g2 = H(PointToString(private_point));
	}
	else return;
}

void ReceiveForeverFromGateway(){
	TCPListener server;
	server.Bind(port);
	server.Listen(20);

	uint8_t index = 0;
	string response = "";
	cout << "ReceiveForeverFromGateway()\n";
	while (run)
	{
		TCPClient client = server.Accept();
		
		client_connect[index] = async(Exec, client);

		index++;
		if (index == 200) index = 0;

		this_thread::sleep_for(chrono::milliseconds(10));
	}
	server.Close();
}

void GetGroupKey(string group){

		string t1 = key_eg_chain.top() + "h", t2 = key_b + "h";
		Integer a(t1.c_str()), b(t2.c_str());
		Integer c = a.Or(b);
		stringstream ss;
		ss << hex << c;

		if (group == "G1"){
			key_group1 = H(ss.str().substr(0, ss.str().length()-1));
		}
		else if (group == "G2"){
			key_group2 = H(ss.str().substr(0, ss.str().length()-1));
		}
	
}

void Exec(TCPClient client){

	string msg = client.Receive(2048);
	if (msg.length() < 1) return;
	vector<string> package = StringSplit(msg, SEPARATION);
	string response = "";
	
	if (package[0] == CONNECT){

		response = ACCEPT + SEPARATION;
		
		MyAES myaes;
		key_eg = key_eg_chain.top();

		GetGroupKey(package[1]);

		if (package[1] == "G1") {
			myaes.SetKeyFromHexString(key_eu1);
			response += myaes.Encryption(THIS_NODE_NAME+SEPARATION+key_group1+SEPARATION+key_eg);
			gateway1 = client;
		}
		else if (package[1] == "G2") {
			myaes.SetKeyFromHexString(key_eu2);
			response += myaes.Encryption(THIS_NODE_NAME+SEPARATION+key_group2+SEPARATION+key_eg);
			gateway2 = client;
		}
		

		key_eg_chain.pop();
		
		client.Send(response);
		return;
	}
	else if (package[0] == ECC_DH){
		ECC_DH_key_exchange(client, msg);
	}
	else if (package[0] == SEND_DATA){
		int tmp = msg.length() - (package.end()->length()+1);

		if (package[1] == "G1") {
			
			MyAES myaes;
			myaes.SetKeyFromHexString(session_key_g1);
			cout << myaes.Decryption(package[2]) << endl;
			if (_HMAC(msg.substr(0, tmp), key_group1) == package[3]) cout << "OK\n";
			else cout << "False\n";

		}
		else if (package[1] == "G2") {
			
			MyAES myaes;
			myaes.SetKeyFromHexString(session_key_g2);
			cout << myaes.Decryption(package[2]) << "\t";
			if (_HMAC(msg.substr(0, tmp), key_group2) == package[3]) cout << "OK\n";
			else cout << "False\n";

		}
	}
	else if (package[0] == FORWARD_TO_EDGE){
		if (*package.end() == "G1"){
			int tmp = msg.length() - ((package.end()-1)->length()+package.end()->length()+1);
			cout << msg << "\t";
			if (_HMAC(msg.substr(0, tmp), key_group1) == package[3]) cout << "OK\n";
			else cout << "False\n";

		}
		else if (*package.end() == "G2"){
			int tmp = msg.length() - ((package.end()-1)->length()+package.end()->length()+1);
			cout << msg << "\t";
			if (_HMAC(msg.substr(0, tmp), key_group2) == package[3]) cout << "OK\n";
			else cout << "False\n";

		}
	}


	client.Close();

	if (key_eg_chain.empty()) CreateChain();

}

void Run(){
	cout << "Running...\n";

	string msg1 = "", msg2 = "";
	MyAES myaes;

	while (run)
	{

		string t1 = key_eg_chain.top() + "h", t2 = key_a + "h";
		Integer a(t1.c_str()), b(t2.c_str());
		Integer c = a.Or(b);
		stringstream ss;
		ss << hex << c;

		string session_key = H(ss.str().substr(0, ss.str().length()-1));

		msg1 = FORWARD_TO_NODE + SEPARATION;
		msg2 = msg1;

		myaes.SetKeyFromHexString(session_key);
		msg1 += (myaes.Encryption("test_hello") + SEPARATION);
		myaes.SetKeyFromHexString(session_key);
		msg2 += (myaes.Encryption("test_hello") + SEPARATION);
		
		if(key_eg_chain.empty()) CreateChain();
		myaes.SetKeyFromHexString(key_group1);
		msg1 += myaes.Encryption(key_eg_chain.top());
		key_eg_chain.pop();

		if(key_eg_chain.empty()) CreateChain();
		myaes.SetKeyFromHexString(key_group2);
		msg2 += myaes.Encryption(key_eg_chain.top());
		key_eg_chain.pop();

		gateway1.Send(msg1);
		gateway2.Send(msg2);

		key_a = H(key_a);
		key_b = H(key_b);

		GetGroupKey("G1");
		GetGroupKey("G2");

		this_thread::sleep_for(chrono::seconds(120));
	}

	run = false;
}

