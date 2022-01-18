#include "invoker.h"
#include "nativesData.h"



NativeArg_s nativeArg;
u64 args[30];

void setVectors() {
	while (nativeArg.vectorCount) {
		nativeArg.vectorCount--;
		
		Vector3* argVector = nativeArg.argVectors[nativeArg.vectorCount];
		Vector4 tempVector = nativeArg.tempVectors[nativeArg.vectorCount];
		argVector->x = tempVector.x;
		argVector->y = tempVector.y;
		argVector->z = tempVector.z;
	}
}

void callHash(u64 hash) {
	#if GAME_VERSION == 100
	for(int i = 0; i <= sizeof(nativesHashes_100) / sizeof(nativesHashes_100[0]); i++) {
		if(nativesHashes_100[i] == hash) {
			((void(*)(NativeArg_s*))nativesFunctions_100[i])(&nativeArg);
		}
	}
	 #elif GAME_VERSION == 113
	 for(int i = 0; i <= sizeof(nativesHashes_113) / sizeof(nativesHashes_113[0]); i++) {
		if(nativesHashes_113[i] == hash) {
			((void(*)(NativeArg_s*))nativesFunctions_113[i])(&nativeArg);
		}
	}
	 #elif GAME_VERSION == 119
	 for(int i = 0; i <= sizeof(nativesHashes_119) / sizeof(nativesHashes_119[0]); i++) {
		if(nativesHashes_119[i] == hash) {
			((void(*)(NativeArg_s*))nativesFunctions_119[i])(&nativeArg);
		}
	}
	 #elif GAME_VERSION == 124
	 for(int i = 0; i <= sizeof(nativesHashes_124) / sizeof(nativesHashes_124[0]); i++) {
		if(nativesHashes_124[i] == hash) {
			((void(*)(NativeArg_s*))nativesFunctions_124[i])(&nativeArg);
		}
	}
	#elif GAME_VERSION == 129
	 for(int i = 0; i <= sizeof(nativesHashes_129) / sizeof(nativesHashes_129[0]); i++) {
		if(nativesHashes_129[i] == hash) {
			((void(*)(NativeArg_s*))nativesFunctions_129[i])(&nativeArg);
		}
	}
	#endif
}



void resetArgs() {
	nativeArg.argCount = 0;
	nativeArg.vectorCount = 0;
	nativeArg.argValues = nativeArg.returnValue = args;
}