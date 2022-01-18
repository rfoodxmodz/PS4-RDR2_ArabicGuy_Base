void givePedWeapon(Ped ped, Hash weapon) {
    _GIVE_WEAPON_TO_PED_2(ped, weapon, 100, true, true, 0, false, 0.5f, 1.0f, 752097756, true, 0.0f, false);
}
void playSound(char* sound, char* sound_dict) {
	PLAY_SOUND_FRONTEND(sound, "PAUSE_MENU_SOUNDSET", 1, 10);
}
void print(const char* text, int nothing = NULL) {
	const char* literalString = CREATE_STRING(10, "LITERAL_STRING", text);
	_LOG_SET_CACHED_OBJECTIVE(literalString);
	_LOG_PRINT_CACHED_OBJECTIVE();
	_LOG_CLEAR_CACHED_OBJECTIVE();
}
bool Match(const unsigned char* pData, const unsigned char* bMask, const char* szMask)
{
    for(;*szMask;++szMask,++pData,++bMask)
	if(*szMask=='x' && *pData!=*bMask ) 
	return false;
    return (*szMask) == 0;
}
u64 find_signature(u64 dwAddress, u64 dwLen, unsigned char *bMask, char* size) {
    for(int i=0; i < dwLen; i++) {
        if(Match((unsigned char*)(dwAddress+i),bMask,size) ) {
            return (u64)(dwAddress+i);
		}
	}
    return 0;
}