#include "ThreadHub.h"

ThreadHub::ThreadHub() {
	RoutineCount = 0;
	for (int i = 0; i < MAX_THREAD_COUNT; ++i) {
		RoutineType[i] = Undefined;
		RoutineAddress[i] = NULL;
		RoutineState[i] = Standby;
	}
}

size_t ThreadHub::AddRoutine(ThreadRoutine Function, ThreadType type) {
	RoutineType[RoutineCount] = type;
	RoutineAddress[RoutineCount] = Function;
	RoutineState[RoutineCount] = Standby;
	return RoutineCount++;
}

void ThreadHub::SetState(ThreadRoutine Function, ThreadState state, int RoutineNum) {
	if (RoutineNum != -1) {
		RoutineState[RoutineNum] = state;
		return;
	}
	for (int i = 0; i < RoutineCount; ++i) {
		if (RoutineAddress[i] == Function) {
			RoutineState[i] = state;
			break;
		}
	}
}

void ThreadHub::StartRoutine(ThreadRoutine Function, int RoutineNum) {
	SetState(Function, Running, RoutineNum);
	if (RoutineNum != -1) {
		RoutineThread[RoutineNum] = std::thread(RoutineAddress[RoutineNum]);
		return;
	}
	for (int i = 0; i < RoutineCount; ++i) {
		if (RoutineAddress[i] == Function) {
			RoutineThread[i] = std::thread(RoutineAddress[i]);
			break;
		}
	}
}

void ThreadHub::JoinRoutine(ThreadRoutine Function, int RoutineNum) {
	if (RoutineNum != -1) {
		if (RoutineThread[RoutineNum].joinable())
			RoutineThread[RoutineNum].join();
		return;
	}
	for (int i = 0; i < RoutineCount; ++i) {
		if (RoutineAddress[i] == Function) {
			if (RoutineThread[i].joinable())
				RoutineThread[i].join();
			break;
		}
	}
}

void ThreadHub::JoinAll() {
	for(int i=0;i<RoutineCount;++i)
		if (RoutineThread[i].joinable())
			RoutineThread[i].join();
}

void ThreadHub::SetConfigJSON(rapidjson::Document *config) {
	configJSON = config;
}