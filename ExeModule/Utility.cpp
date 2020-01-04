#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <WinInet.h>
#include <wincrypt.h>
#include "Utility.h"
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Wininet.lib")

wchar_t* ctow(wchar_t *pwstr, const char *str) {
	if (str) {
		size_t nu = strlen(str);
		memset(pwstr, 0, 2 * nu + 2);
		size_t n = (size_t)MultiByteToWideChar(CP_ACP, 0, (const char *)str, nu, NULL, 0);
		MultiByteToWideChar(CP_ACP, 0, (const char *)str, int(nu), pwstr, n);
	}
	return pwstr;
}

void byte2Hex(unsigned char bData, unsigned char hex[]) {
	int high = bData / 16, low = bData % 16;
	hex[0] = (high <10) ? ('0' + high) : ('A' + high - 10);
	hex[1] = (low <10) ? ('0' + low) : ('A' + low - 10);
}

#pragma region BinaryData
long long BinaryData::modexp(long long a, long long b, long long n) {
	long long ret = 1;
	long long tmp = a;
	while (b) {
		if (b & 0x1) ret = ret*tmp%n;
		tmp = tmp*tmp%n;
		b >>= 1;
	}
	return ret;
}

std::size_t BinaryData::rabin_karp_find(char *src, std::size_t src_len, char *pattern, std::size_t p_len) {
	int d = 0xff;
	std::size_t prime = 982451653;
	long long h = modexp(d, p_len - 1, prime);
	std::size_t p = 0, t = 0;
	for (std::size_t i = 0; i<p_len; i++) {
		p = (d*p + pattern[i]) % prime;
		t = (d*t + src[i]) % prime;
	}
	for (std::size_t s = 0; s <= src_len - p_len; s++) {
		if (p == t && memcmp(pattern, src + s, p_len) == 0)
			return s;
		if (s<src_len - p_len)
			t = (d*(t - src[s] * h) + src[s + p_len]) % prime;
	}
	return -1;
}

void BinaryData::allocate(std::size_t sz, const char *src) {
	if (src == nullptr) {
		is_empty = true;
		return;
	}
	if (!is_empty) {
		delete[] data;
		data = nullptr;
	}
	data = new char[sz];
	memcpy(data, src, sz);
	is_empty = false;
	size = sz;
}
//insert the data before the indicated position
void BinaryData::insert(std::size_t start, const char *src, std::size_t len) {
	char *buf = new char[len + size];
	if (start > 0)
		memcpy(buf, data, start);
	memcpy(buf + start, src, len);
	memcpy(buf + start + len, data + start, size - start);
	allocate(size + len, buf);
	delete[] buf;
}

std::size_t BinaryData::find(char *d, std::size_t len) {
	return rabin_karp_find(data, size, d, len);
}

void BinaryData::erase(std::size_t start, std::size_t end, bool eat) {
	if (eat) {
		memmove(data + start, data + end, size - end);
		size -= end - start;
		return;
	}
	while (start < end)
		data[start++] = 0;
}

BinaryData::BinaryData() {
	data = nullptr;
	is_empty = true;
	size = 0;
}

BinaryData::BinaryData(const BinaryData &bd) {
	data = nullptr;
	is_empty = true;
	allocate(bd.size, bd.data);
}

BinaryData::BinaryData(size_t sz, const char *src) {
	is_empty = true;
	data = nullptr;
	allocate(sz, src);
}

BinaryData::~BinaryData() {
	if (!is_empty);
	delete[] data;
}

BinaryData& BinaryData::operator=(const BinaryData &rhs) {
	allocate(rhs.size, rhs.data);
	return *this;
}

BinaryData operator+(const BinaryData &bd1, const BinaryData &bd2) {
	size_t NewSize = bd1.GetSize() + bd2.GetSize();
	BinaryData ret(NewSize, bd1.GetData());
	memcpy(ret.GetData() + bd1.GetSize(), bd2.GetData(), bd2.GetSize());
	return ret;
}

BinaryData& BinaryData::operator+=(const BinaryData& bd) {
	*this = *this + bd;
	return *this;
}

char& BinaryData::operator[](const std::size_t index) {
	return data[index];
}

const char& BinaryData::operator[](const std::size_t index) const {
	return data[index];
}

char* BinaryData::GetData() const {
	return data;
}

size_t BinaryData::GetSize() const {
	return size;
}

void BinaryData::SetData(char *src, std::size_t len) {
	allocate(len, src);
}

BinaryData::State BinaryData::SaveToFile(char *path) {
	FILE *file;
	fopen_s(&file, path, "wb");
	if (!file)
		return OpenFail;
	fwrite(data, sizeof(char), size, file);
	fclose(file);
	return Success;
}
#pragma endregion

#pragma region Crypto
bool Crypto::Base64Decode(IN BinaryData *input, OUT BinaryData *output) {
	char *chBase64Data = input->GetData();
	DWORD dwBase64DataLen = 0;
	BYTE *pbOutBuffer = NULL;
	DWORD dwOutBufferLen = 0;

	dwBase64DataLen = strlen(input->GetData());

	if (!CryptStringToBinaryA(chBase64Data, dwBase64DataLen, CRYPT_STRING_BASE64, NULL, &dwOutBufferLen, NULL, NULL))
		return false;

	pbOutBuffer = (BYTE*)malloc(dwOutBufferLen + 1);
	if (pbOutBuffer != NULL)
		memset(pbOutBuffer, 0, dwOutBufferLen + 1);
	else
		return false;

	if (!CryptStringToBinaryA(chBase64Data, dwBase64DataLen, CRYPT_STRING_BASE64, pbOutBuffer, &dwOutBufferLen, NULL, NULL))
		return false;

	output->SetData((char*)pbOutBuffer, dwOutBufferLen + 1);
	output->GetData()[dwOutBufferLen] = '\0';
	chBase64Data = NULL;
	if (pbOutBuffer) {
		free(pbOutBuffer);
		pbOutBuffer = NULL;
	}
	return true;
}

bool Crypto::Base64Encode(IN BinaryData *input, OUT BinaryData *output) {
	BYTE *pbBuffer = (BYTE*)input->GetData();
	DWORD dwBufferLen = strlen((char*)pbBuffer);
	char *chBase64Data = NULL;
	DWORD dwBase64DataLen = 0;

	if (!CryptBinaryToString(pbBuffer, dwBufferLen, CRYPT_STRING_BASE64, NULL, &dwBase64DataLen))
		return false;

	chBase64Data = (char*)malloc(dwBase64DataLen + 1);
	if (chBase64Data != NULL)
		memset(chBase64Data, 0, dwBase64DataLen + 1);
	else
		return false;

	if (!CryptBinaryToStringA(pbBuffer, dwBufferLen, CRYPT_STRING_BASE64, chBase64Data, &dwBase64DataLen))
		return false;

	chBase64Data[dwBase64DataLen - 1] = '\0';
	output->SetData(chBase64Data, dwBase64DataLen + 1);

	if (chBase64Data) {
		free(chBase64Data);
		chBase64Data = NULL;
	}
	return true;
}

std::string Crypto::generate_10_rand() {
	std::string ret;
	srand(time(nullptr));
	for (int i = 0; i < TiebaObfuscateKeyLength; i++) {
		int t = rand() % TiebaObfuscateKeyLength;
		ret += t + 48;
	}
	return ret;
}

char Crypto::alpha_offset(char c, int k) {
	k %= 26;
	if (isupper(c)) {
		if (c + k <= 'Z')
			return c + k;
		else
			return c + k - 'Z' + 'a' - 1;
	}
	else if (islower(c)) {
		if (c + k <= 'z')
			return c + k;
		else
			return c + k - 'z' + 'A' - 1;
	}
}

char Crypto::recover_alpha_offset(char c, int k) {
	k %= 26;
	if (islower(c)) {
		if (c - k < 'a')
			return 'Z' - k + (c - 'a') + 1;
		else
			return c - k;
	}
	else if (isupper(c)) {
		if (c - k < 'A')
			return 'z' - k + (c - 'A') + 1;
		else
			return c - k;
	}
}

std::string Crypto::TextObfuscate(IN BinaryData *input, OUT std::string *key, IN ObfuscateType Type) {
	InternetUtility internetUtility;
	if (Type == Base64Tieba) {
		std::string id = generate_10_rand();
		if (internetUtility.RandFromTieba(id) == internetUtility.WebMessageOpenFail)
			return internetUtility.WebMessageOpenFail;

		while (internetUtility.RandFromTieba(id) == internetUtility.WebMessagePage404)
			id = generate_10_rand();
		std::string MapList = internetUtility.RandFromTieba(id);
		if (MapList == internetUtility.WebMessageOpenFail)
			return internetUtility.WebMessageOpenFail;

		for (int i = 0; i < MapList.length(); i++) {
			MapList[i] = (unsigned)MapList[i] % 26;
		}
		BinaryData output;
		*key = id;
		int offset;
		if (Base64Encode(input, &output)) {
			std::string ret(output.GetData());
			std::string::iterator p_map = MapList.begin();
			std::string::iterator p_text = ret.begin();
			while (p_text != ret.end() && *p_text != '\0') {
				if (isalpha(*p_text)) {
					*p_text = alpha_offset(*p_text, *p_map);
				}
				p_map++, p_text++;
				if (p_map == MapList.end())
					p_map = MapList.begin();
			}
			ret[ret.size()] = '\0';
			return ret;
		}
	}
}

std::string Crypto::DecodeTextObfuscate(IN BinaryData *input, IN std::string *key, IN ObfuscateType Type) {
	InternetUtility internetUtility;
	if (Type == Base64Tieba) {
		std::string MapList = internetUtility.RandFromTieba(*key);
		if (MapList == internetUtility.WebMessageOpenFail || MapList == internetUtility.WebMessagePage404)
			return MapList;

		for (int i = 0; i < MapList.length(); i++) {
			MapList[i] = (unsigned)MapList[i] % 26;
		}

		std::string text(input->GetData());
		std::string::iterator p_text = text.begin();
		std::string::iterator p_maplist = MapList.begin();
		while (p_text != text.end() && *p_text != '\0') {
			if (isalpha(*p_text))
				*p_text = recover_alpha_offset(*p_text, *p_maplist);
			p_text++, ++p_maplist;
			if (p_maplist == MapList.end())
				p_maplist = MapList.begin();
		}
		BinaryData output(text.length() + 1, text.c_str());
		BinaryData ret;
		Base64Decode(&output, &ret);
		std::string r(ret.GetData());
		return r;
	}
}
#pragma endregion

#pragma region InternetUtility
std::string InternetUtility::UTF8_To_string(const std::string & str) {
	int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	wchar_t * pwBuf = new wchar_t[nwLen + 1];//一定要加1，不然会出现尾巴
	memset(pwBuf, 0, nwLen * 2 + 2);
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
	int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
	char * pBuf = new char[nLen + 1];
	memset(pBuf, 0, nLen + 1);
	WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
	std::string retStr = pBuf;
	delete[]pBuf;
	delete[]pwBuf;
	pBuf = NULL;
	pwBuf = NULL;
	return retStr;
}

std::string InternetUtility::ReadUntil(std::string &in, size_t start_pos, char until) {
	std::string ret;
	for (int i = start_pos; in[i] != until; ++i)
		ret += in[i];
	return ret;
}

bool InternetUtility::CheckUrlConnection(std::string url) {
	return InternetCheckConnectionA(url.c_str(), FLAG_ICC_FORCE_CONNECTION, 0);
}

int InternetUtility::CheckInternetState() {
	DWORD dwFlag;
	if (!InternetGetConnectedState(&dwFlag, 0))
		return Offline;
	else if (dwFlag & INTERNET_CONNECTION_MODEM)
		return ModemConnected;
	else if (dwFlag & INTERNET_CONNECTION_LAN)
		return LANConnected;
	else if (dwFlag & INTERNET_CONNECTION_PROXY)
		return ProxyConnected;
	else if (dwFlag & INTERNET_CONNECTION_MODEM_BUSY)
		return ModemBusy;
}

int InternetUtility::CheckInternetConnection() {
	DWORD dwFlag;
	if (!InternetGetConnectedState(&dwFlag, 0))
		return Offline;
	else if (dwFlag & INTERNET_CONNECTION_MODEM_BUSY)
		return Offline;
	else if (dwFlag)
		return Online;
}

int InternetUtility::HttpRequest(IN std::string method, std::string hostname, std::string api, IN std::string parameter, OUT std::string &receive, IN std::string Cookie, IN bool fHeader) {
	WSADATA wsaData;
	WSAStartup(WINSOCK_VERSION, &wsaData);

	hostent *host_addr = gethostbyname(hostname.c_str());
	if (!host_addr) return WebOpenError;

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons((unsigned short)80);
	sin.sin_addr.s_addr = *((int*)*host_addr->h_addr_list);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) return InitError;
	if (connect(sock, (const struct sockaddr *)&sin, sizeof(sockaddr_in)) == -1)
		return ConnectionError;

	std::string send_str, form;
	if (method == "POST")
		send_str += "POST ";
	else if (method == "GET")
		send_str += "GET ";
	send_str += api;
	send_str += " HTTP/1.1\r\n";
	send_str += "Host: ";
	send_str += hostname;
	send_str += "\r\n";
	send_str += "Connection: keep-alive\r\n";

	char buf[32];
	std::string header = "Content-Length: ";
	_itoa(parameter.length(), buf, 10);
	header += buf;
	header += "\r\n";

	send_str += header;
	send_str += "Cache-Control: max-age=0\r\n";
	send_str += std::string("Origin: ") + hostname + "\r\n";
	send_str += "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36\r\n";
	send_str += "Content-Type: application/x-www-form-urlencoded\r\n";
	send_str += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
	send_str += std::string("Referer: ") + api + "\r\n";
	//send_str += "Accept-Encoding: gzip, deflate\r\n";
	send_str += "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n";
	if (Cookie != "")
		send_str += std::string("Cookie: ") + Cookie + "\r\n";

	send_str += "\r\n";
	send_str += parameter;
	if (send(sock, send_str.c_str(), send_str.length(), 0) == -1)
		return SendError;

	receive.clear();
	char szReceive[4096];
	int state = 1;
	if (fHeader) {
		if (recv(sock, szReceive, sizeof(szReceive), 0) == -1)
			return RecvError;
		receive = std::string(szReceive);
	}
	else {
		while (state > 0) {
			ZeroMemory(szReceive, sizeof(szReceive));
			state = recv(sock, szReceive, sizeof(szReceive), 0);
			receive += szReceive;
		}
	}
	WSACleanup();
	return Success;
}

int InternetUtility::PostAndReceive(IN std::string hostname, IN std::string api, IN std::string parameter, OUT std::string &receive, IN std::string Cookie, IN bool fHeader) {
	return HttpRequest("POST", hostname, api, parameter, receive, Cookie, fHeader);
}

int InternetUtility::GetAndReceive(IN std::string hostname, IN std::string api, IN std::string parameter, OUT std::string &receive, IN std::string Cookie, IN bool fHeader) {
	return HttpRequest("GET", hostname, api, parameter, receive, Cookie, fHeader);
}

int InternetUtility::RegisterPOJAccount(std::string &Username, std::string &Password) {
	int ret;
	std::string parameter = "user_id=";
	parameter += Username + "&nick=";
	parameter += Username + "&password=";
	parameter += Password + "&rptPassword=";
	parameter += Password + "&school=wKmeds&email=K0000@lwox.com&submit=Submit";

	std::string szRecv;
	ret = PostAndReceive(POJHostName, POJRegisterPage, parameter, szRecv);
	if (ret != Success)
		return ret;
	if (szRecv.find("Accept-Encoding") != std::string::npos)
		return Success;
	else return POJRegisterFail;
}
//JSession will be set to " JSESSIONID=XXXXXXXX " by default
int InternetUtility::LoginPOJGetJSession(IN std::string Username, IN std::string UserPwd, OUT std::string &JSession, bool Extract) {
	std::string strResponse, receive;
	int ret;
	if ((ret = GetAndReceive(POJHostName, POJMainPage, std::string(""), strResponse, std::string("t"))) != Success)
		return ret;
	size_t pos = strResponse.find("JSESSIONID=");
	if (pos == std::string::npos) {
		JSession.clear();
		return POJLoginFail;
	}
	JSession.assign(strResponse.begin() + pos, strResponse.begin() + strResponse.find("; Path=/"));
	std::string parameter = std::string("user_id1=") + Username + std::string("&password1=") + UserPwd + std::string("&B1=login&url=%2F");
	ret = PostAndReceive(POJHostName, POJLoginPage, parameter, receive, JSession);
	std::string loginTest;
	GetAndReceive(POJHostName, POJSendPage, std::string(""), loginTest, JSession);
	if (loginTest.find(Username.c_str()) == std::string::npos)
		return POJLoginFail;
	if (Extract)
		JSession.assign(strResponse.begin() + pos + strlen("JSESSIONID="), strResponse.begin() + strResponse.find("; Path=/"));
	return Success;
}
//JSession will be set to " ;jsessionid=xxxxxxxxx "
int InternetUtility::LoginPOJGetJSessionNoCookie(IN std::string Username, IN std::string UserPwd, OUT std::string &JSession, bool Extract) {
	//Under construction
	return Success;
}

int InternetUtility::SendMessageToPOJAccount(IN std::string DestAccount, IN std::string SrcAccount, IN std::string SrcPasswd, IN std::string Title, IN std::string Content) {
	std::string JSessionId;
	int ret = LoginPOJGetJSession(SrcAccount, SrcPasswd, JSessionId);
	if (JSessionId.empty()) return ret;
	if (ret == POJLoginFail) return ret;
	std::string receive, parameter;
	for (std::string::iterator i = Title.begin(); i != Title.end(); i++)
		if (*i == ' ') *i = '+';
	for (std::string::iterator i = Content.begin(); i != Content.end(); i++)
		if (*i == ' ') *i = '+';
	parameter = "to=";
	parameter += DestAccount + "&title=" + Title + "&content=" + Content + "&b1=Send";
	PostAndReceive(POJHostName, POJSendPage, parameter, receive, JSessionId);
	if (receive.find("Accept-Encoding") != std::string::npos)
		return Success;
	else
		return POJSendFail;
}

//Generate random numbers from BaiduTieba with the seed id
std::string InternetUtility::RandFromTieba(std::string id) {
	/* make sure the connection is well-established before calling the function
	"\'forumName\': \'"				4 chars
	"author=\""						8 chars
	"\'threadTitle\': \'"			20 chars
	"j_d_post_content  clearfix\">"	20 chars
	*/
	std::string keyword[4] = { "\'forumName\': \'","author=\"","\'threadTitle\': \'","j_d_post_content  clearfix\">" };
	int len[4] = { 4,8,20,20 };
	std::string urlTieba = TiebaUrl;
	std::string url = urlTieba + id;
	std::string src = GetWebSource(url.c_str());
	std::string ret;

	if (src.find("/errorpage/getGoodThread") != std::string::npos)
		return WebMessagePage404;

	char tmp;
	if (src == WebMessageOpenFail)
		return WebMessageOpenFail;
	else {
		for (int i = 0; i < 4; i++) {
			size_t index = src.find(keyword[i]);
			for (int j = 0; j < len[i]; j++) {
				tmp = abs(src[index + strlen(keyword[i].c_str()) + j]) % 26;
				ret += tmp;
			}
		}
		return ret;
	}
}

int InternetUtility::UploadJPGToTietuku(BinaryData &jpgData, std::string &Url) {
	std::string webSrc = GetWebSource(TietuUploadPage.c_str());
	if (webSrc == WebMessageOpenFail)
		return WebOpenError;
	std::string Token, tokenBegin("var token=\'"), tokenEnd(";\nvar allownum=");
	if (webSrc.find(tokenBegin.c_str()) == std::string::npos)
		return WebOpenError;
	Token.assign(webSrc.begin() + webSrc.find(tokenBegin.c_str()) + tokenBegin.length(), webSrc.begin() + webSrc.find(tokenEnd.c_str()) - 1);
	std::string request_payload, boundary = "------WebKitFormBoundaryFireh0rsexxxxxCc";
	std::string b1;
	b1.assign(boundary.begin() + 2, boundary.end());
	request_payload.clear();
	request_payload = boundary + "\r\n";
	request_payload += "Content-Disposition: form-data; name=\"Token\"\r\n\r\n";
	request_payload += Token + "\r\n";
	request_payload += boundary + "\r\n";
	request_payload += "Content-Disposition: form-data; name=\"file\"; filename=\"pic.jpg\"\r\n";
	request_payload += "Content-Type: image/jpeg\r\n\r\n";
	BinaryData payload(request_payload.length(), request_payload.c_str());
	payload += jpgData;
	request_payload.clear();
	request_payload += "\r\n" + boundary + "\r\n";
	request_payload += "Content-Disposition: form-data; name=\"from\"\r\n\r\n";
	request_payload += "file\r\n";
	request_payload += boundary + "\r\n";
	request_payload += "Content-Disposition: form-data; name=\"httptype\"\r\n\r\n";
	request_payload += "1\r\n";
	request_payload += boundary + "--\r\n\r\n";
	BinaryData payload1(request_payload.length(), request_payload.c_str());
	payload += payload1;
	char b[20];
	std::string header = "POST / HTTP/1.1\r\n"
		"Host: " + TietuAPIHost + "\r\n"
		"Connection: keep-alive\r\n"
		"Content-Length: " + std::string(_ltoa(payload.GetSize(), b, 10)) + "\r\n"
		"Accept: */*\r\n"
		"Origin: null\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36\r\n"
		"Content-Type: multipart/form-data; boundary=" + b1 + "\r\n"
		"Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n\r\n";
	BinaryData request(header.length(), header.c_str());
	request += payload;
	char szReceive[4096];
	memset(szReceive, 0, sizeof(szReceive));
	WSADATA wsaData;
	WSAStartup(WINSOCK_VERSION, &wsaData);
	hostent *host_addr = gethostbyname(TietuAPIHost.c_str());
	if (!host_addr) return TietuOpenError;
	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons((unsigned short)80);
	sin.sin_addr.s_addr = *((int*)*host_addr->h_addr_list);
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) return InitError;
	if (connect(sock, (const struct sockaddr *)&sin, sizeof(sockaddr_in)) == -1)
		return ConnectionError;
	if (send(sock, request.GetData(), request.GetSize(), 0) == -1)
		return SendError;
	int len;
	if ((len = recv(sock, (char*)szReceive, sizeof(szReceive), 0)) == -1)
		return RecvError;
	WSACleanup();
	std::string recvStr(szReceive);
	if (recvStr.find("[img]") == std::string::npos)
		return RecvError;
	recvStr.assign(recvStr.begin() + recvStr.find("[img]") + strlen("[img]"), recvStr.begin() + recvStr.find("[\\/img]"));
	Url.clear();
	for (auto i = recvStr.begin(); i != recvStr.end(); i++)
		if (*i != '\\') Url += *i;
	return Success;
}

int InternetUtility::GetJPGData(IN std::string JPGUrl, OUT BinaryData &Data) {
	//Under construction
	std::string HostName = GetHostNameFromUrl(JPGUrl);
	int state = GetAndReceive(HostName, JPGUrl, "", HostName, "", false);
	return 0;
}

//returns WebMessageOpenFail if fails
std::string InternetUtility::GetWebSource(const char *Url, bool ConvertFromUtf8)
{
	const int MAXBLOCKSIZE = 4 * 4096;
	HINTERNET hSession = InternetOpen(TEXT("zwt"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	std::string src;
	if (hSession != NULL) {
		HINTERNET hURL = InternetOpenUrlA(hSession, Url, NULL, 0, INTERNET_FLAG_DONT_CACHE, 0);
		if (hURL != NULL) {
			char Temp[MAXBLOCKSIZE] = { 0 };
			ULONG Number = 1;
			while (Number > 0) {
				InternetReadFile(hURL, Temp, MAXBLOCKSIZE - 1, &Number);
				src += Temp;
			}

			InternetCloseHandle(hURL);
			hURL = NULL;
		}
		InternetCloseHandle(hSession);
		hSession = NULL;
	}
	if (src.empty())
		return WebMessageOpenFail;
	if (ConvertFromUtf8)
		src = UTF8_To_string(src);
	return src;
}

int InternetUtility::Download(const char *Url, BinaryData &output) {
	const int MAXBLOCKSIZE = 4096;
	byte Temp[MAXBLOCKSIZE];
	ULONG Number = 1;
	HINTERNET hSession = InternetOpen(TEXT("RookIE/1.0"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hSession != NULL) {
		HINTERNET handle2 = InternetOpenUrlA(hSession, Url, NULL, 0, INTERNET_FLAG_DONT_CACHE, 0);
		if (handle2 != NULL) {
			while (Number > 0) {
				InternetReadFile(handle2, Temp, MAXBLOCKSIZE - 1, &Number);
				BinaryData tmp(Number, (char*)Temp);
				output += tmp;
			}
			InternetCloseHandle(handle2);
			handle2 = NULL;
		}
		InternetCloseHandle(hSession);
		hSession = NULL;
	}
	if (output.GetSize())
		return Success;
	else
		return WebOpenError;
}

InternetUtility::State InternetUtility::GenerateKeywordFromBaiduNews(int length, std::string &key, size_t offset) {
	std::string webSrc = GetWebSource(BaiduNews.c_str());
	if (webSrc == WebMessageOpenFail) {
		key = WebMessageOpenFail;
		return WebOpenError;
	}

	std::string sign(".htm\">");
	std::string sign_null(".");
	std::string str;
	size_t pos;
	for (int i = 0; i < offset; ++i) {
		if ((pos = webSrc.find(sign)) != std::string::npos) {
			webSrc.replace(webSrc.begin() + pos, webSrc.begin() + pos + sign.length(), sign_null.c_str());
		}
	}
	if ((pos = webSrc.find(sign)) != std::string::npos) {
		for (int i = 0; i < 32; ++i) {
			long n = 0;
			n += webSrc[pos + sign.length() + i];
			n = abs(n);
			if (n % 3 == 0)
				str += (char)(n % 10 + '0');
			else if (n % 3 == 1)
				str += (char)(n % 26 + 'a');
			else if (n % 3 == 2)
				str += (char)(n % 26 + 'A');
		}
	}
	key.assign(str.begin(), str.begin() + length);
	return Success;
}

int InternetUtility::LoginGetPOJMailList(std::string UserName, std::string UserPwd, OUT MailList &mailList, OUT std::string &JSession) {
	std::string JSessionId;
	int ret = LoginPOJGetJSession(UserName, UserPwd, JSessionId);
	if (JSessionId.empty()) return ret;
	if (ret == POJLoginFail) return ret;
	JSession = JSessionId;
	return GetPOJMailListWithJSession(JSessionId, mailList);
}

std::string InternetUtility::GetHostNameFromUrl(std::string Url) {
	size_t start_pos = 0;
	std::string szhttp("http://"), szhttpw("http://www."), szwww("www.");
	if (Url.find(szhttpw) != std::string::npos)
		start_pos = szhttpw.length();
	else if (Url.find(szhttp) != std::string::npos)
		start_pos = szhttp.length();
	else if (Url.find(szwww) != std::string::npos)
		start_pos = szwww.length();
	auto i = Url.begin() + start_pos;
	std::string ret;
	while (i != Url.end() && *i != '/' && *i != ':')
		ret += *i++;
	return ret;
}

int InternetUtility::GetPOJMailListWithJSession(IN std::string JSession, OUT MailList &mailList) {
	std::string recv;
	int state = GetAndReceive(POJHostName, POJMailPage, "", recv, JSession, false);
	if (state != Success)
		return state;

	std::string szShowMail = "showmail?mail_id=";
	size_t pos;
	mailList.clear();
	while ((pos = recv.find(szShowMail)) != std::string::npos) {
		std::string href;
		std::string sz_locate;
		std::string szTitle, szContent;
		for (size_t i = pos + szShowMail.length(); recv[i] != '>'; ++i) {
			href += recv[i];
		}
		sz_locate = href + "><font color=blue>";
		size_t pos_title = recv.find(sz_locate);
		for (size_t i = pos_title + sz_locate.length(); recv[i] != '<'; ++i) {
			szTitle += recv[i];
		}
		href = POJMainPage + szShowMail + href;
		std::string pre_tag = "<pre>";
		std::string content;
		if (GetAndReceive(POJHostName, href, "", content, JSession, false) == Success) {
			std::string tmp;
			size_t content_pos = content.find(pre_tag);
			for (size_t i = content_pos + pre_tag.length(); content[i] != '<'; ++i) {
				tmp += content[i];
			}
			szContent = tmp;
		}
		if (szContent.empty())
			state = POJGetMessageFail;
		mailList.push_back(make_pair(szTitle, szContent));
		recv.replace(recv.begin() + pos, recv.begin() + pos + szShowMail.length(), ".");
	}
	if (state != POJGetMessageFail)
		return Success;
	else
		return state;
}

int InternetUtility::GetMessageFromSina(IN std::string keyword, OUT std::vector<std::string> &Message) {
	std::string url_detour = std::string(WeiboHuati) + keyword + "?from=faxian";
	std::string detour = GetWebSource(url_detour.c_str());
	std::string sign("var url = \"");
	std::string url = ReadUntil(detour, detour.find(sign) + sign.length(), '\"');
	std::string websrc;
	int state = GetAndReceive(WeiboHostName, url, "", websrc, "SINAGLOBAL=1234567890987.6543.2123456789098; UOR=book.51cto.com,widget.weibo.com,www.cnblogs.com; SUB=_theresonly24hoursinaday7qZIt_ww_andhalfofthoseRl-youlaywm3RA4XGvyYpJYiiA_6GP1Avv_b0OsKw..; SUBP=0033WrSXaaaaaa2-Ws9jqgbojackhorseman4k7qJdzN-9breobcUPo5; YF-Page-G0=280e58c5ca896750f16dcc47ceb234ed; _s_tentry=-; Apache=4503567370298.716.1480484204651; ULV=1480484204662:13:13:6:4503567370298.716.1480484204651:1480484078371", false);
	if (state != Success)
		return state;
	size_t pos;
	while ((pos = websrc.find("\\")) != std::string::npos)
		websrc.replace(websrc.begin() + pos, websrc.begin() + pos + 1, "");
	sign = std::string("#") + keyword + "#" + "</a>";

	while ((pos = websrc.find("<br>")) != std::string::npos) {
		websrc.replace(websrc.begin() + pos, websrc.begin() + pos + 4, "\n");
	}
	for (int t = 0; t < 3; ++t) {
		if (t == 1)
			transform(sign.begin(), sign.end(), sign.begin(), tolower);
		else if (t == 2)
			transform(sign.begin(), sign.end(), sign.begin(), toupper);
		while ((pos = websrc.find(sign)) != std::string::npos) {
			std::string str = ReadUntil(websrc, pos + sign.length(), '<');
			size_t spos;
			while ((spos = str.find("\n")) != std::string::npos)
				str.replace(str.begin() + spos, str.begin() + spos + 1, "");
			while ((spos = str.find("\r")) != std::string::npos)
				str.replace(str.begin() + spos, str.begin() + spos + 1, "");
			while ((spos = str.find(" ")) != std::string::npos)
				str.replace(str.begin() + spos, str.begin() + spos + 1, "");
			for (int i = 64+TiebaObfuscateKeyLength; i < str.length(); i += 66)
				str.insert(i, " \n");
			Message.push_back(str);
			websrc.replace(websrc.begin() + pos, websrc.begin() + pos + sign.length(), "");
		}
	}
	return Success;
}
#pragma endregion