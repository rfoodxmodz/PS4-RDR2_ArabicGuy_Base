#include "types.h"
#include "enums.h"
#include "vars.h"
#include "lib.h"
#include "offsets.h"
#include "natives.h"
#include "extraNatives.h"
#include "gameFunctions.h"
#include "drawing.h"
#include "utils.h"
#include "functions.h"

void monitorButtons() {
	Static_67 = GET_FRAME_COUNT();
	if ( !( GET_FRAME_COUNT() - Static_67 >= 2 ) ) {
		testT = true;
	} else testT = false;
	Static_67 = GET_FRAME_COUNT();
	if (NumMenu == Closed) {
		if (IS_DISABLED_CONTROL_PRESSED(0, INPUT_FRONTEND_RB) && IS_DISABLED_CONTROL_PRESSED(0, INPUT_FRONTEND_X)) {
			NumMenu = Main_Menu;
			NumMenuLevel = 0;
			currentOption = 1;
			playSound("HUD_DRAW", "HUD_DUEL_SOUNDSET");
		}
	}
	else {
		if(testT) {
			if (check_button(FrontendCancel, 0)) {
				if (NumMenu == Main_Menu) {
					NumMenu = Closed;
				}
				else {
					NumMenu = lastNumMenu[NumMenuLevel - 1];
					currentOption = lastOption[NumMenuLevel - 1];
					NumMenuLevel--;
				}
				playSound("BACK", "PAUSE_MENU_SOUNDSET");
			}
			else if (check_button(FrontendAccept, 0)) {
				PressX = true;
				playSound("ACCEPT", "PAUSE_MENU_SOUNDSET");
			}
			else if (check_button(FrontendUp, 1)) {
				currentOption--;
				if (currentOption < 1) {
					currentOption = optionCount;
				}
				playSound("BUMPER_LEFT", "PAUSE_MENU_SOUNDSET");
			}
			else if (check_button(FrontendDown, 1)) {
				currentOption++;
				if (currentOption > optionCount) {
					currentOption = 1;
				}
				playSound("BUMPER_LEFT", "PAUSE_MENU_SOUNDSET");
			}
			else if (check_button(FrontendRight, 1)) {
				rightPress = true;
				playSound("BUMPER_LEFT", "PAUSE_MENU_SOUNDSET");
			}
			else if (check_button(FrontendLeft, 1)) {
				leftPress = true;
				playSound("BUMPER_LEFT", "PAUSE_MENU_SOUNDSET");
			}
		}
	}
}
void actionsController() {
	DISABLE_CONTROL_ACTION(2, INPUT_NEXT_CAMERA, true);
	DISABLE_CONTROL_ACTION(2, INPUT_VEH_SELECT_NEXT_WEAPON, true);
	DISABLE_CONTROL_ACTION(2, INPUT_HUD_SPECIAL, true);
	DISABLE_CONTROL_ACTION(2, INPUT_FRONTEND_ACCEPT, true);
	DISABLE_CONTROL_ACTION(2, INPUT_FRONTEND_CANCEL, true);
	DISABLE_CONTROL_ACTION(2, INPUT_FRONTEND_LEFT, true);
	DISABLE_CONTROL_ACTION(2, INPUT_FRONTEND_RIGHT, true);
	DISABLE_CONTROL_ACTION(2, INPUT_FRONTEND_DOWN, true);
	DISABLE_CONTROL_ACTION(2, INPUT_FRONTEND_UP, true);
	DISABLE_CONTROL_ACTION(2, INPUT_CHARACTER_WHEEL, true);
	DISABLE_CONTROL_ACTION(2, INPUT_MULTIPLAYER_INFO, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SPRINT, true);
	DISABLE_CONTROL_ACTION(2, INPUT_PHONE, true);
	DISABLE_CONTROL_ACTION(2, MeleeHorseAttackPrimary, true);
	DISABLE_CONTROL_ACTION(2, MeleeHorseAttackSecondary, true);
	DISABLE_CONTROL_ACTION(2, MeleeGrappleAttack, true);
	DISABLE_CONTROL_ACTION(2, MeleeAttack, true);
	DISABLE_CONTROL_ACTION(2, INPUT_MAP, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SELECT_WEAPON_UNARMED, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SELECT_WEAPON_MELEE, true);
	DISABLE_CONTROL_ACTION(2, INPUT_ATTACK2, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SCRIPT_PAD_UP, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SCRIPT_PAD_DOWN, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SCRIPT_PAD_LEFT, true);
	DISABLE_CONTROL_ACTION(2, INPUT_SCRIPT_PAD_RIGHT, true);
	SET_INPUT_EXCLUSIVE(2, INPUT_FRONTEND_CANCEL);
	SET_INPUT_EXCLUSIVE(2, INPUT_FRONTEND_DOWN);
	SET_INPUT_EXCLUSIVE(2, INPUT_FRONTEND_UP);
	SET_INPUT_EXCLUSIVE(2, INPUT_FRONTEND_LEFT);
	SET_INPUT_EXCLUSIVE(2, INPUT_FRONTEND_RIGHT);
	SET_INPUT_EXCLUSIVE(2, INPUT_FRONTEND_X);
	DRAW_RECT(Menu_X, 0.1177f, CenterDraw, 0.080f,BannerR, BannerG, BannerB, 150, 0, 0);
	if (NumMenu != Closed) {
		if (InfoText != NULL) {
			if (optionCount > maxOptions) {
				DRAW_TEXT(InfoText, 0, 0.758 - 0.125, ((maxOptions + 2.2080) * 0.030f + 0.125f), 0.35f, 0.35f, 255, 255, 255, 255, false, false, 0, 0, 0);
				DRAW_RECT(Menu_X, (((maxOptions + 2.2080) * 0.030f) + 0.1415f), CenterDraw, 0.035f, BannerR, BannerG, BannerB, 150, 0, 0); //Info Box
			}
			else {
				DRAW_TEXT(InfoText, 0, 0.758- 0.125, ((optionCount + 2.2080) * 0.030f + 0.125f), 0.35f, 0.35f, 255, 255, 255, 255, false, false, 0, 0, 0);
				DRAW_RECT(Menu_X, (((optionCount + 2.2080) * 0.030f) + 0.1415f), CenterDraw, 0.035f, BannerR, BannerG, BannerB, 150, 0, 0); //Info Box
			}
		}
		if (optionCount > maxOptions) {
			DRAW_TEXT("Ver: 1.0", 0, 0.758 - 0.125, ((maxOptions + 1) * 0.030f + 0.125f), 0.32f, 0.32f, 255, 255, 255, 255, false, false, 0, 0, 0);
			char buffer[30];
			snprintf(buffer, sizeof(buffer), "~bold~%i/%i", currentOption, optionCount);
			drawTextCounter(buffer, 0, 0.758 + 0.102, ((maxOptions + 1) * 0.030f + 0.125f), 0.32f, 0.32f, 255, 255, 255, 200); //option count
			DRAW_RECT(Menu_X, (((maxOptions + 1) * 0.030f) + 0.1415f), CenterDraw, 0.035f, BannerR, BannerG, BannerB, 150, 0, 0); //Info Box
		}
		else {
			DRAW_TEXT("Ver: 1.0", 0, 0.758- 0.125, ((optionCount + 1) * 0.030f + 0.125f), 0.32f, 0.32f, 255, 255, 255, 255, false, false, 0, 0, 0);
			char buffer[30];
			snprintf(buffer, sizeof(buffer), "~bold~%i/%i", currentOption, optionCount);
			drawTextCounter(buffer, 0, 0.758 + 0.102, ((optionCount + 1) * 0.030f + 0.125f), 0.32f, 0.32f, 255, 255, 255, 200); //option count
			DRAW_RECT(Menu_X, (((optionCount + 1) * 0.030f) + 0.1415f), CenterDraw, 0.035f, BannerR, BannerG, BannerB, 150, 0, 0); //Info Box
		}
	}
}
void looping()
{
	if (NeverWanted) {
		#if GAME_VERSION != 100
			CLEAR_PLAYER_WANTED_LEVEL(PLAYER_ID());
			SET_MAX_WANTED_LEVEL(0);
			#else
			SET_MAX_WANTED_LEVEL_2(0);
		#endif
	}
	if(Invisibility) {
		SET_ENTITY_VISIBLE(PLAYER_PED_ID(), false);
	}
	if(Forcefield) {
		Vector3 Coords = GET_ENTITY_COORDS(PLAYER_PED_ID(), false, false);
		ADD_EXPLOSION(Coords.x, Coords.y, Coords.z, 29, 20.0, false, true, 0.0f);
	}
	if(SuperJump) {
		Player player = PLAYER_ID();
		SET_SUPER_JUMP_THIS_FRAME(player);
	}
	if(SuperRun) {
		if (IS_CONTROL_PRESSED(0, FrontendAccept) && NumMenu == Closed) {
			APPLY_FORCE_TO_ENTITY(PLAYER_PED_ID(), true, 0, 15, 0, 0, 0, 0, false, true, true, true, 0, true);
			APPLY_FORCE_TO_ENTITY(PLAYER_PED_ID(), true, 0, 0, 0, 0, 0, 0, false, true, true, true, 0, true);
		}
	}
	if(GodMode) {
		SET_PLAYER_INVINCIBLE(PLAYER_ID(), true);
	}
}
void menu(void) {
	drawScroller();
	optionCount = 0;
	if(NumMenu == Main_Menu) {
		AddTitle("ArabicGuy");
		addOption("Player",  1, "");
		addOption("Credits",  0, "");
		if(GET() == 1) {
			ChangeMenu(PlayerMenu);
		}
		if(GET() == 2) {
			ChangeMenu(Credits);
		}
	}
	else if(NumMenu == PlayerMenu) {
		AddTitle("Player");
		CheckBox("GodMode", GodMode, 0, "");
		CheckBox("Never Wanted", NeverWanted, 1, "");
		CheckBox("Super Run", SuperRun, 0, "Press X to use super run.");
		CheckBox("Super Jump", SuperJump, 1, "");
		CheckBox("Forcefield", Forcefield, 0, "");
		CheckBox("Invisibility", Invisibility, 1, "");
		CheckBox("Freeze Position", FreezePos, 0, "");
		if(GET() == 1) {
			GodMode = !GodMode;
		}
		else if(GET() == 2) {
			NeverWanted = !NeverWanted;
			if (NeverWanted == false) {
				#if GAME_VERSION != 100
					SET_MAX_WANTED_LEVEL(6);
					#else
					SET_MAX_WANTED_LEVEL_2(6);
				#endif
			}
		}
		else if(GET() == 3) {
			SuperRun =! SuperRun;
		}
		else if(GET() == 4) {
			#if GAME_VERSION != 100
				SuperJump =!SuperJump;
			#endif
		}
		else if(GET() == 5) {
			Forcefield =!Forcefield;
		}
		else if(GET() == 6) {
			Invisibility = !Invisibility;
			if(Invisibility == false) {
				SET_ENTITY_VISIBLE(PLAYER_PED_ID(), true);
			}	
		}
		else if(GET() == 7) {
			FreezePos =! FreezePos;
			FREEZE_ENTITY_POSITION(PLAYER_PED_ID(), FreezePos);
		}
	}
	else if(NumMenu == Credits) {
		AddTitle("Credits");
		addOption("rfoodxmodz", 1, "");;
		addOption("2much4u", 0, "");
	}
	if(NumMenu != Closed)
	actionsController();
}
extern "C" void _main(void) {
	if(!init) {
		initLibs();
		setTextData = reinterpret_cast<text_info*>(TEXT_INFO_POINTER);
		init = true;
	}
		int FrameCount = GET_FRAME_COUNT();
		if (FrameCount > frameCount) {
			frameCount = FrameCount;
			looping();
			monitorButtons();
			if(NumMenu != Closed) {
				menu();
				resetVars();
			}
	}
}