#include "ps4.h"

#include "kern.h"
#include "proc.h"
#include "rdr.h"

extern char rdrPayload[];
extern int rdrPayloadSize;
int gamePID;
int gameVersion;
u64 RDR_HookAddress;
u64 RDR_PayloadAddress;
double(*ceil)(double x);
int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message);
int(*sceNetGetMacAddress)(SceNetEtherAddr *addr, int flags);
void sysNotify(char* msg) {
	sceSysUtilSendSystemNotificationWithText(222, msg);
}

BOOL regionCheck() {
	procAttach(gamePID);
	unsigned char gameCheck;
	procReadBytes(gamePID, regionAddr, (void*)&gameCheck, sizeof(gameCheck));
	BOOL success = FALSE;
	switch (gameCheck)
	{
		case 0x5C://1.00
		//write FPS patch here
		RDR_HookAddress = 0x2129DFB;
		RDR_PayloadAddress = 0x66A6BE0;
		gameVersion = 100;
	    success = TRUE;
	    sysNotify("Detected Game.\nYour Version 1.00.");
		break;
		case 0x02://1.13
		RDR_HookAddress = 0x2665421;
		RDR_PayloadAddress = 0x6FB3200;
		gameVersion = 113;
	    success = TRUE;
	    sysNotify("Detected Game.\nYour Version 1.13.");
		break;
		case 0x41://1.19
		RDR_HookAddress = 0x2147A01;
		RDR_PayloadAddress = 0x710E178;
		gameVersion = 119;
	    success = TRUE;
	    sysNotify("Detected Game.\nYour Version 1.19.");
		break;
		case 0xE9://1.24
		RDR_HookAddress = 0x2186E51;
		RDR_PayloadAddress = 0x71E0DE0;
		gameVersion = 124;
	    success = TRUE;
	    sysNotify("Detected Game.\nYour Version 1.24.");
		break;
		case 0xC7://1.29
		RDR_HookAddress = 0x21C4E31;
		RDR_PayloadAddress = 0x7631690;
		gameVersion = 129;
	    success = TRUE;
	    sysNotify("Detected Game.\nYour Version 1.29.");
		break;
		default:
		sysNotify("Failed to detect RDR 2\n.");
		break;
	}
	procDetach(gamePID);
	return success;
}
BOOL setupDone() {
	procAttach(gamePID);

	BOOL allocationNeeded;
	procReadBytes(gamePID, &gtaVars->allocationNeeded, &allocationNeeded, sizeof(allocationNeeded));

	procDetach(gamePID);
	return !allocationNeeded;
}

Inline void* sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
	u64 _syscall = ((u64(*)(int num, ...))(void*)SyscallAddress)(477, addr, len, prot, flags, fd, offset);
	return (void*)_syscall;
}

int nativeHook(u64 RDI) {
	if (gtaVars->allocationNeeded) {
		if (!gtaVars->executableSpace) {
			gtaVars->executableSpace = sys_mmap((void*)0x926200000, gtaVars->allocationSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		}
		else if (!gtaVars->dataSpace) {
			gtaVars->dataSpace = sys_mmap((void*)0x926300000, gtaVars->allocationSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		}
		else {
			*(char*)gtaVars->executableSpace = 0xC3;
			gtaVars->allocationNeeded = FALSE;
		}
	}
	else {
		((void(*)())gtaVars->executableSpace)();
	}

	return TRUE;
}
void runSetup() {
	procAttach(gamePID);
	BOOL allocationNeeded = TRUE;
	procWriteBytes(gamePID, &gtaVars->allocationNeeded, &allocationNeeded, sizeof(allocationNeeded));
	
	void* null = NULL;
	procWriteBytes(gamePID, &gtaVars->executableSpace, &null, sizeof(null));
	procWriteBytes(gamePID, &gtaVars->dataSpace, &null, sizeof(null));
	
	int executableSize = (int)ceil((double)rdrPayloadSize / 0x4000) * 0x4000;
	procWriteBytes(gamePID, &gtaVars->allocationSize, &executableSize, sizeof(executableSize));
	
	u8 syscallASM[] = { SyscallBytes };
	procWriteBytes(gamePID, SyscallAddress, syscallASM, sizeof(syscallASM));
	
	procWriteBytes(gamePID, (void*)RDR_PayloadAddress, nativeHook, 0x3000);
	
	if(gameVersion == 100) {
		u8 hookASM[] = { HookBytes_100 };
		procWriteBytes(gamePID, (void*)RDR_HookAddress, hookASM, sizeof(hookASM));
	}
	if(gameVersion == 113) {
		u8 hookASM[] = { HookBytes_113 };
		procWriteBytes(gamePID, (void*)RDR_HookAddress, hookASM, sizeof(hookASM));
	}
	if(gameVersion == 119) {
		u8 hookASM[] = { HookBytes_119 };
		procWriteBytes(gamePID, (void*)RDR_HookAddress, hookASM, sizeof(hookASM));
	}
	if(gameVersion == 124) {
		u8 hookASM[] = { HookBytes_124 };
		procWriteBytes(gamePID, (void*)RDR_HookAddress, hookASM, sizeof(hookASM));
	}
	if(gameVersion == 129) {
		u8 hookASM[] = { HookBytes_129 };
		procWriteBytes(gamePID, (void*)RDR_HookAddress, hookASM, sizeof(hookASM));
	}
	procDetach(gamePID);
}
void startExecution() {
	procAttach(gamePID);
	
	void* executableSpace;
	procReadBytes(gamePID, &gtaVars->executableSpace, &executableSpace, sizeof(executableSpace));
	
	procWriteBytes(gamePID, executableSpace, rdrPayload, rdrPayloadSize);
	
	procDetach(gamePID);
}

int _main(void) {
	initKernel();
	initLibc();
	
	uint64_t fw_version = get_fw_version();
	jailbreak(fw_version);
	
	
	int libc = sceKernelLoadStartModule("libSceLibcInternal.sprx", 0, NULL, 0, 0, 0);
	int sysUtil = sceKernelLoadStartModule("/system/common/lib/libSceSysUtil.sprx", 0, NULL, 0, 0, 0);
	RESOLVE(sysUtil, sceSysUtilSendSystemNotificationWithText);
	RESOLVE(libc, ceil);
	sysNotify("ArabicGuy V1.0 Menu loaded.\nPlease launch RDR2.");
	gamePID = findProcess("eboot.bin");
	
	sceKernelSleep(3);
	
	if (!regionCheck()) {
		return 0;
	}
	
	sysNotify("Setting up environment.");
	runSetup();
	
	while (!setupDone()) sceKernelSleep(3);
	sceKernelSleep(5);
	startExecution();
	sysNotify("ArabicGuy Menu Activated.\nEnjoy!");
	return 0;
}
