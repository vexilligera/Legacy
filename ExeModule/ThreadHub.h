#pragma once
#include <thread>
#include "rapidjson\document.h"
#include "rapidjson\writer.h"
#include "rapidjson\stringbuffer.h"
#include "Environment.h"

typedef void(*ThreadRoutine)();
enum ThreadState { Standby = 0, Running, Done, Error };

typedef struct _RoutineExtension {
	void *Parameter;
	size_t SizeofParameter;
}RoutineExtension, *PRoutineExtension;

class ThreadHub {
public:
	enum ThreadSignal { Run, Stop };
	enum ThreadType { Maintainance = 0, System, Internet, Undefined = 128 };
	ThreadHub();
	size_t AddRoutine(ThreadRoutine Function, ThreadType type);
	void SetState(ThreadRoutine Function, ThreadState state, int RoutineNum = -1);
	void StartRoutine(ThreadRoutine Function, int RoutineNum = -1);
	void JoinRoutine(ThreadRoutine Function, int RoutineNum = -1);
	void JoinAll();
	void SetConfigJSON(rapidjson::Document *config);
private:
	static const size_t MAX_THREAD_COUNT = 128;
	std::thread RoutineThread[MAX_THREAD_COUNT];
	ThreadRoutine RoutineAddress[MAX_THREAD_COUNT];
	ThreadType RoutineType[MAX_THREAD_COUNT];
	ThreadState RoutineState[MAX_THREAD_COUNT];
	RoutineExtension Extension[MAX_THREAD_COUNT];
	size_t RoutineCount;
	rapidjson::Document *configJSON;
	Environment environment;
};