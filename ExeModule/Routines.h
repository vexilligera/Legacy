#pragma once
#include "rapidjson\document.h"
#include "rapidjson\writer.h"
#include "rapidjson\stringbuffer.h"
#include "ThreadHub.h"
#include "Utility.h"
#include "ShellCmd.h"

class InternetRoutine {
	friend class MessageRoutine;
public:
	InternetRoutine() :MsgRoutine(nullptr) {}
	void InternetMainThread();
	void SetMessageRoutine(MessageRoutine *msgRoutine);
	void SetThreadHub(ThreadHub *th);
	void SetMainStub(ThreadRoutine mainStub);
private:
	InternetUtility internetUtility;
	bool fInternetConnection;
	bool fOnline;
	MessageRoutine *MsgRoutine;
	ThreadHub *threadHub;
	ThreadRoutine MainStub;
};

class MessageRoutine {
	friend class InternetRoutine;
private:
	struct Message {
		std::string Keyword;
		std::string ObfuscateKey;
		std::string DecryptedMessage;
		int State;
	};
	std::vector<Message> messageQueue;
	ThreadHub *threadHub;
	ThreadRoutine MainStub;
	enum ParseResult { pop, keep, error };
	bool locked;
public:
	void AddMessage(std::string Keyword, std::string ObfuscateKey, std::string DecryptedMessage);
	Message SearchMessage(std::string ObfuscateKey);
	bool RemoveMessage(std::string ObfuscateKey);
	void MessageMainThread();
	ParseResult ParseMessage(std::string msg);
	void MessageRoutine::SetThreadHub(ThreadHub *th);
	void SetMainStub(ThreadRoutine mainStub);
	void Expunge();
};