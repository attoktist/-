#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//----------------------------------------------------------------------------Ч 
#include <winsock2.h>
#include <stdio.h> 
#include <string> 
#include <iostream>
#include <fstream>
#include <cwchar>
#include <memory>
#include <conio.h>
#include <stdlib.h>
#include <mstcpip.h>
#include <WS2tcpip.h>
#include <cstdio>



#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ws2_32.lib")

//----------------------------------------------------------------------------Ч 
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";
using namespace std;
//using namespace System;
//using namespace System::Net;
//using namespace System::Security;
//using namespace System::ServiceProcess;
//using namespace System::Security::Cryptography::X509Certificates;

static inline bool is_base64(unsigned char c)
{
	return (isalnum(c) || (c == '+') || (c == '/'));
}

string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len)
{
	string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i <4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}

string base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i <4; i++)
				char_array_4[i] = (const unsigned char)base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j <4; j++)
			char_array_4[j] = 0;

		for (j = 0; j <4; j++)
			char_array_4[j] = (const unsigned char)base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}
//----------------------------------------------------------------------------Ч 
int get_addr(char *host_name)
{
	int res = -1;

	HOSTENT *phe = gethostbyname(host_name);
	if (phe)
		for (int i = 0; i < 4; i++)
			((BYTE *)&res)[i] = phe->h_addr_list[0][i];

	return res;
}
//----------------------------------------------------------------------------Ч 
int kl; // количество адресов в группе

void create_address_group()
{
	cout << "¬ведите количество адресов дл€ создани€ группы адресов\n";
	cin >> kl;
	while (kl <= 0)
	{
		cout << "¬ведено неверное значение. ¬ведите количество адресов дл€ создани€ группы адресов\n";
		cin >> kl;
	}
	string *addr = new string[kl];
	for (int i = 0; i < kl; i++)
	{
		cout << "јдрес: ";
		cin >> addr[i];
	}
	string name_group;
	cout << "¬ведите им€ группы\n";
	cin >> name_group;
	ofstream out("Address/" + name_group + ".txt");
	out << kl << endl;
	for (int i = 0; i < kl; i++)
	{
		out << addr[i] + "\n";
	}
	out.close();
}

string *load_group_list(string name_group)
{
	ifstream in(name_group);

	in >> kl;
	string *addr = new string[kl];

	for (int i = 0; i < kl; i++)
	{
		in >> addr[i];
		cout << i + 1 + "." << addr[i] << endl;
	}

	return addr;
}
//-------------------------------------------------------------------------------------------


bool _send(SOCKET s, const string &message)
{
	printf("u: %s", message.c_str());
	if (!send(s, message.c_str(), message.length(), 0)) return false;

	return true;
}
//----------------------------------------------------------------------------Ч 
char buffer[4096];
bool _recv(SOCKET s, const unsigned code)
{
	
	int buffer_size = recv(s, buffer, sizeof(buffer), 0);
	if (!buffer_size) return false;
	buffer[buffer_size] = 0;
	printf("s: %s", buffer);

	unsigned _code;
	if (sscanf(buffer, "%u", &_code) != 1 || _code != code) return false;



	return true;
}
//----------------------------------------------------------------------------Ч 
bool _send_and_recv(SOCKET s, const std::string &message, const unsigned code)
{
	return _send(s, message) && _recv(s, code);
}



SSL *ssl;
char buf[4096];

void write(const char *s) {
	int err = SSL_write(ssl, s, strlen(s));
	printf("> %s\n", s);

}

void read() {
	int n = SSL_read(ssl, buf, sizeof(buf) - 1);

	if (n == 0) {
		int e = SSL_get_error(ssl, 0);
		printf("Read error %i\n", e);
		exit(1);
	}
	buf[n] = 0;
	printf("%s\n", buf);
}
//----------------------------------------------------------------------------Ч 

int number;

void send_mail(const unsigned smtp_port, const std::string	&smtp_addr, const std::string &login,
	const std::string &password, const std::string &name, const std::string &from,
	const std::string &to, const std::string &data)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) exit(-1);

	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(smtp_port);
	sa.sin_addr.S_un.S_addr = get_addr((char *)smtp_addr.c_str());

			
	//printf("wait for server...");

	printf("wait for server...");
	while (connect(s, (SOCKADDR *)&sa, sizeof(sa)))
		Sleep(250);
	printf("connected\n");

	//bool res =
	_recv(s, 220);
	if (number == 1) _send_and_recv(s, "HELO " + name + "\r\n", 250);
	else if (number == 2) _send_and_recv(s, "EHLO " + name + "\r\n", 250);
	_send_and_recv(s, "AUTH LOGIN\r\n", 334);
	_send_and_recv(s, base64_encode((const unsigned char*)login.c_str(), login.length()) + "\r\n", 334);
	_send_and_recv(s, base64_encode((const unsigned char*)password.c_str(), password.length()) + "\r\n", 235);
	_send_and_recv(s, "MAIL FROM:<" + from + ">\r\n", 250);
	_send_and_recv(s, "RCPT TO:<" + to + ">\r\n", 250);
	_send_and_recv(s, "DATA\r\n", 354);
	_send(s, data) &&
		_send_and_recv(s, "\r\n.\r\n", 250);
	_send_and_recv(s, "QUIT\r\n", 221);
	closesocket(s);
}
//----------------------------------------------------------------------------Ч 



string get_mail(const unsigned pop3_port, const std::string	&smtp_addr,
	const std::string &login, const std::string &password, const std::string &data)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) exit(1);
	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(pop3_port);
	sa.sin_addr.S_un.S_addr = get_addr((char *)smtp_addr.c_str());	
	printf("wait for server...");
	bool con = false;
	char buf2[1024] = { 0 };
	while (!con)
	{
		if ((connect(s, (SOCKADDR *)&sa, sizeof(sa))) == SOCKET_ERROR)
		{
			printf("Error pop3 connect.\n");
		}
		else if (connect(s, (SOCKADDR *)&sa, sizeof(sa)))
		{
			printf("connected\n");
			_send(s, login);    _recv(s, 334);
			_send(s, password); _recv(s, 334);
			//_send(s, data);
			_send(s, data);

			for (int i = 0; i < 2; i++)
			{
				_recv(s, 334);
			}
			con = true;
			break;
		}

	}
	printf("\n\n");	
	closesocket(s);
	string arr(buf2);
	return arr;
}




void TransferWCHAR(string login)
{
	unique_ptr<wchar_t[]> temp = nullptr;
	int t = 1000;
	login = "c:\\mail\\" + login;
	const char* temp2 = login.c_str();
	//temp = (wchar_t*)temp2;
	//t = mbstowcs(nullptr, temp2, 0);
	temp.reset(new wchar_t[t]);
	if (mbstowcs(temp.get(), temp2, 255) == 1) { cout << "Eror"; }
	_wmkdir(temp.get());
	temp.reset(nullptr);
	temp = nullptr;

}

void trigger_mail(string login,string password,string message)
{
	string name_group="trigger_list";
	/*cout << "¬ведите им€ группы: ";
	cin >> name_group;

	cout << "Message "; cin >> message;*/

	string *addr = load_group_list("Address/" + name_group + ".txt");

	for (int i = 0; i < kl; i++)
	{
		TransferWCHAR(login);
		send_mail(25, "smtp.rambler.ru", login, password, "user", login, addr[i], message);
	}
}

void savemail(string login, string data, string login2)
{
	SYSTEMTIME st;
	string filename;
	GetSystemTime(&st);
	int day = st.wDay;
	int mounth = st.wMonth;
	int year = st.wYear;
	filename = to_string(day) + "." + to_string(mounth) + "." + to_string(year) + ".txt";
	fopen(filename.c_str(), "w");
	FILE* file = fopen(filename.c_str(), "w");
	ofstream out("c:\\mail\\" + login + "\\" + filename);
	out << "Your Adress " + login << endl;
	out << "Adress To " + login2 << endl;
	out << "Data " + data << endl;
	out.close();
}




int main(int argc, char* argv[])
{
	//ServicePointManager::SecurityProtocol = SecurityProtocolType::Tls11;
	setlocale(LC_ALL, "Russian");
	string message;
	string login;
	string data;
	string login2;
	string password;
	WSADATA wsa_data;
	int n;
	if (WSAStartup(0x101, &wsa_data) || wsa_data.wVersion != 0x101) return -1;


	OPENSSL_init();


	LPCWCHAR path = L"с:\\mail";
	/*if (CreateDirectory(path, NULL))
	{
		cout << "CREATE";
	}*/
	cout << "«дравствуйте\n"
		<< "ѕочтовый клиент запущен\n"
		<< "¬ыберите действие" << "\n"
		<< "1 - ќтправить сообщение\n"
		<< "2 - ѕрин€ть сообщение\n"
		<< "3 - √руппова€ рассылка письма\n"
		<< "4 - —оздание адресной группы\n"
		<< "5 - ќтправка сообщени€ на почту из адресной книги\n";

	cin >> n;
	cout << "јвторизуйтесь" << endl;
	cout << "Login "; cin >> login;
	cout << "Pass "; //cin >> password;
	char *mass = (char *)malloc(sizeof(char) * 100);
	int i = 0;
	mass[i] = _getch();
	cout << "*";
	while (mass[i] != '\r')
	{
		i++;
		mass[i] = _getch();
		cout << "*";
	}
	for (int f = 0; f<i; f++)
		password += mass[f];
	free(mass);
	mass = NULL;
	cout << endl;

	switch (n)
	{
	case 1: {//SMTP
		cout << "¬ыберите протокол\n1 - smtp\n2 - esmtp\n";
		cin >> number;
		while ((number < 0) || (number > 2))
		{
			cout << "Ќеверное значение. ¬ведите правильное значение\n";
			cin >> number;
		}
		cout << "Message "; cin >> message;
		cout << "Adress To "; cin >> login2;
		TransferWCHAR(login);
		send_mail(25, "smtp.rambler.ru", login, password, "user", login, login2, message);
		savemail(login, message, login2);
		break;
	}
	case 2: {//POP3
		login2 = "—писок команд которые вы ввели";
		int m;
		cout << "¬ведите номер операции\n"
			<< "1 - ѕолучить сообщение\n"
			<< "2 - ”далить сообщение\n";
		cin >> m;
		int k;
		cout << "¬ведите номер сообщени€\n";
		cin >> k;

		switch (m)
		{
		case 1:
		{
			char s[5];
			itoa(k, s, 10);
			string a(s);
			get_mail(110, "pop.rambler.ru", "User " + login + "\r\n", "Pass " + password + "\r\n", "Retr " + a + "\r\n");
			if ((strstr(buffer, "trigger") || strstr(buffer, "TRIGGER")))
			{
				message = "Trigger mailing";
				trigger_mail(login, password, message);
			}
			string aa(buffer);
			savemail(login, aa, login2);
		}break;
		case 2:
		{
			char s[5];
			itoa(k, s, 10);
			string a(s);
			get_mail(110, "pop.rambler.ru", "User " + login + "\r\n", "Pass " + password + "\r\n", "DELE " + a + "\r\n");
			string aa(buffer);
			savemail(login, aa, login2);
		}break;
		default: break;
		}
		//cin >> message;
		//message = message + " 1";
		//scanf("%s", &message);
		/*TransferWCHAR(login);
		get_mail(110, "pop.rambler.ru", "User " + login + "\r\n", "Pass " + password + "\r\n", message + "\r\n");*/
		//savemail(login, msg, login2);
		break;
	}

	case 3:
	{
		string name_group;
		cout << "¬ведите им€ группы: ";
		cin >> name_group;

		cout << "Message "; cin >> message;

		string *addr = load_group_list("Address/" + name_group + ".txt");

		for (int i = 0; i < kl; i++)
		{
			TransferWCHAR(login);
			send_mail(25, "smtp.rambler.ru", login, password, "user", login, addr[i], message);
		}

	}break;
	case 4: // создание адресной группы
	{
		create_address_group();
		//load_group_list("Address/first.txt");
	}break;

	case 5:
	{
		string name_group("address_list");
		string *addr = load_group_list("Address/" + name_group + ".txt");
		int n;//номер в адресной книге
		cout << "¬ведите номер электронной почты из списка выше:";
		cin >> n;
		cout << "Message "; cin >> message;
		TransferWCHAR(login);
		send_mail(25, "smtp.rambler.ru", login, password, "user", login, addr[n - 1], message);

	}

	default: break;
	}

	WSACleanup();
	system("pause");
	return 0;
}