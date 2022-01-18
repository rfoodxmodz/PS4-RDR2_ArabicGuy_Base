void ChangeMenu(int Menu) {
	lastNumMenu[NumMenuLevel] = NumMenu;
	lastOption[NumMenuLevel] = currentOption;
	currentOption = 1;
	NumMenu = Menu;
	NumMenuLevel++;
}
int GET() {
	if (PressX) {
		return currentOption;
		PressX = false;
	}
	else return 0;
}
void resetVars() {
	PressX = false;
	rightPress = false;
	leftPress = false;
}
void drawScroller() {
	if (optionCount > maxOptions) {
		if (currentOption > maxOptions) {
			DRAW_RECT(0.8900, ((maxOptions *  0.030f) + 0.1410f), 0.0050, 0.0285, SRL_R, SRL_G, SRL_B, 189, 0, 0);
		}
		else {
			DRAW_RECT(0.8900, ((currentOption *  0.030f) + 0.1410f), 0.0050, 0.0285, SRL_R, SRL_G, SRL_B, 189, 0, 0);
		}
	}
	else {
		DRAW_RECT(0.8900, ((currentOption *  0.030f) + 0.1410f), 0.0050, 0.0285, SRL_R, SRL_G, SRL_B, 189, 0, 0);
	}
}
void AddTitle(char* Text, int fontId = 1) {
	DRAW_TEXT2(Text, fontId, Title_X, 0.0840, 0.9000, 0.9000, TITLE_R, TITLE_G , TITLE_B , 255, false);
}
void AddOption(char *option, bool Normal, int color, char* Infox) {
	optionCount++;
	if (currentOption == optionCount)
	InfoText = Infox;
	SelectedItem = false;
	if (optionCount == currentOption) {
		SelectedItem = true;
	}
	if(Normal) {
		if (currentOption <= maxOptions && optionCount <= maxOptions) {
			if(color == 0) {
				DRAW_RECT(Menu_X, (optionCount * 0.030f + 0.1410f), CenterDraw, 0.0285, BKG_R, BKG_G, BKG_B, 189, 0, 0);
			}
			if(color == 1) {
				DRAW_RECT(Menu_X, (optionCount * 0.030f + 0.1410f), CenterDraw, 0.0285, 0, 0, 0, 150, 0, 0);
			}
			DRAW_TEXT_OPTION(option, OptionsFont, Cunt - 0.015 , (optionCount * 0.030f + 0.127f), 0.35000000, 0.35000000, 255, false, false, 0, 0, 0);
		}
		else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
			if(color == 0) {
				DRAW_RECT(Menu_X, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.1410f), CenterDraw, 0.0285, BKG_R, BKG_G, BKG_B, 189, 0, 0);
			}
			if(color == 1) {
				DRAW_RECT(Menu_X,  ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.1410f), CenterDraw, 0.0285,0, 0, 0, 150, 0, 0);
			}
			DRAW_TEXT_OPTION(option, OptionsFont, Cunt - 0.015, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.127f), 0.35000000, 0.35000000, 255, false, false, 0, 0, 0);
		}
	}
	else {
		if (currentOption <= maxOptions && optionCount <= maxOptions) {
			if(color == 0) {
				DRAW_RECT(Menu_X, (optionCount * 0.030f + 0.1410f), CenterDraw, 0.0285, BKG_R, BKG_G, BKG_B, 189, 0, 0);
			}
			if(color == 1) {
				DRAW_RECT(Menu_X, (optionCount * 0.030f + 0.1410f), CenterDraw, 0.0285, 0, 0, 0, 150, 0, 0);
			}
			DRAW_TEXT_OPTION(option, OptionsFont, Cunt, (optionCount * 0.030f + 0.127f), 0.35000000, 0.35000000, 255, false, false, 0, 0, 0);
		}
		else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
			if(color == 0) {
				DRAW_RECT(Menu_X, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.1410f), CenterDraw, 0.0285, BKG_R, BKG_G, BKG_B, 189, 0, 0);
			}
			if(color == 1) {
				DRAW_RECT(Menu_X, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.1410f), CenterDraw, 0.0285, 0, 0, 0, 150, 0, 0);
			}
			DRAW_TEXT_OPTION(option, OptionsFont, Cunt, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.127f), 0.35000000, 0.35000000, 255, false, false, 0, 0, 0);
		}
	}
}
void addOption(char* option, int color, char* Infox) {
	AddOption(option, false, color, Infox);
}
void CheckBox(const char* text, bool toggle, int color, char* Infox = "") {
	char buf[255];
	AddOption(text, false, color, Infox);
	int optionIndex = 0;
	if (currentOption <= maxOptions && optionCount <= maxOptions) {
		DrawSprite("menu_textures", "SELECTION_BOX_SQUARE", 0.8700, ((optionCount) * 0.030f + 0.1413f), 0.0150, 0.0250, 0, 255, 255, 255, 255);
	}
	else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
		DrawSprite("menu_textures", "SELECTION_BOX_SQUARE", 0.8700, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.1413f), 0.0150, 0.0250, 0, 255, 255, 255, 255);
	}
	if (toggle) {
		int optionIndex = 0;
		if (currentOption <= maxOptions && optionCount <= maxOptions) {
			DrawSprite("generic_textures", "TICK", 0.8700, ((optionCount) * 0.030f + 0.1413f), 0.0150, 0.0250, 0, 129, 45, 45, 255);
		}
		else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
			DrawSprite("generic_textures", "TICK", 0.8700, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.1413f), 0.0150, 0.0250, 0, 129, 45, 45, 255);
		}
	}
}
void IntOption(char *option, int *var, int min, int max, bool fast, int color, char* Infox) {
	AddOption(option, false, color, Infox);
	if (currentOption <= maxOptions && optionCount <= maxOptions) {
		drawNumber(*var, 0, 0.868, (optionCount * 0.030f + 0.126f), 0.36f, 0.36f, 255, 255, 255, 255, 1);
	}
	else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
		drawNumber(*var, 0, 0.868, (maxOptions * 0.030f + 0.126f), 0.36f, 0.36f, 255, 255, 255, 255, 1);
	}
	if (currentOption == optionCount) {
		if(fast == false) {
			if (rightPress == true) {
				if (*var >= max) {
					*var = min;
				}
				else {
					*var = *var + 1;
				}
				rightPress = false;
			}
			else if (leftPress == true) {
				if (*var <= min) {
					*var = max;
				}
				else {
					*var = *var - 1;
				}
				leftPress = false;
			}
		}
	}
}
void FloatOption(char *option, float *var, float min, float max, float Default, int color, char* Infox ) {
	AddOption(option, false, color, Infox);
	if (currentOption <= maxOptions && optionCount <= maxOptions) {
	drawFloat(*var, true, 0.858, (optionCount  * 0.030f + 0.1250f), 0.36f, 0.36f, 255, 255, 255, 255);	}
	else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
		drawFloat(*var, true, 0.858, (maxOptions  * 0.030f + 0.1250f), 0.36f, 0.36f, 255, 255, 255, 255);
	}
	if (currentOption == optionCount) {
		if (rightPress == true) {
			if (*var >= max) {
				*var = min;
			}
			else {
				*var = *var + 0.01f;
			}
			rightPress = false;
		}
		else if (leftPress == true) {
			if (*var <= min) {
				*var = max;
			}
			else {
				*var = *var - 0.01f;
			}
			leftPress = false;
		}
		else if(IS_CONTROL_JUST_PRESSED(0, FrontendX)) {
			*var = Default;
		}
	}
}
void TextOption(char *option, char* Text, int *Num, int min, int max, bool SmallFont, bool withoutSPRITE, int color, char* Info) {
	AddOption(option, withoutSPRITE, color, Info);
	if (currentOption <= maxOptions && optionCount <= maxOptions) {
		if (SmallFont == false) {
			DRAW_TEXT(Text, 0, 0.857, (optionCount * 0.030f + 0.127f), 0.35000000f, 0.35000000f, 255, 255, 255, 255, true, false, 0, 0, 0);
		}
		else {
			DRAW_TEXT(Text, 0, 0.820, (optionCount * 0.030f + 0.127f), 0.26000000f, 0.26000000f, 255, 255, 255, 255, 1, false, 0, 0, 0);
		}
	}
	else if ((optionCount > (currentOption - maxOptions)) && optionCount <= currentOption) {
		if (SmallFont == true) {
			DRAW_TEXT(Text, 0, 0.857, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.127f), 0.35000000f, 0.35000000f, 255, 255, 255, 255, false, false, 0, 0, 0);
		}
		else {
			DRAW_TEXT(Text, 0, 0.820, ((optionCount - (currentOption - maxOptions)) * 0.030f + 0.127f), 0.26000000f, 0.26000000f, 255, 255, 255, 255, 1, false, 0, 0, 0);
		}
	}
	if (currentOption == optionCount) {
		if (rightPress == true) {
			if (*Num >= max) {
				*Num = min;
			}
			else {
				*Num = *Num + 1;
			}
			rightPress = false;
		}
		else if (leftPress == true) { 
			if (*Num <= min) {
				*Num = max;
			}
			else {
				*Num = *Num - 1;
			}
			leftPress = false;
		}
	}
}
bool check_button(int buttonID, bool checkSpeed) {
	bool isPressed = false;
	if (IS_DISABLED_CONTROL_JUST_PRESSED(0, buttonID))
	return true;
	if (checkSpeed) {
		if(IS_DISABLED_CONTROL_PRESSED(0, buttonID)) {
			timerScrollSpeed++;
			if (timerScrollSpeed > 7) {
				timerScrollSpeed = 6;
				isPressed = true;
			}
		}
		if (IS_DISABLED_CONTROL_JUST_RELEASED(0, buttonID)) {
			timerScrollSpeed = 0;
		}
	}
	return isPressed;
}
bool delayed_key_press(int control) {
	if (GET_GAME_TIMER() - lastButtonPress < buttonPressDelay) {
		return false;
	}
	if (IS_DISABLED_CONTROL_PRESSED(0, control) == true) {
		lastButtonPress = GET_GAME_TIMER();
		return true;
	}
	return false;
}