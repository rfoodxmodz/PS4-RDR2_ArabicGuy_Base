//Menu Variables
/**Integer**/
int SelClrR = 255;
int SelClrG = 255;
int SelClrB = 0;
int scalex_ = 0;
int scaley_ = 0;
int SRL_R = 255;
int SRL_G = 255;
int SRL_B = 255;
int BKG_R = 91;
int BKG_G = 8;
int BKG_B = 8;
int TITLE_R = 255;
int TITLE_G = 255;
int TITLE_B = 255;
int BannerR = 91;
int BannerG = 8;
int BannerB = 8;
int TitleColor = 1;
int BannersColor = 1;
int BackgroundColor =1;
int ScrollerColor =1;
int TitleFont = 6;
int OptionsFont = 0;
int maxTimerCount;
int timer = 0;
int frameCount = 0;
int TextTimer = 0,
CreditTextTimer = 0,
lastButtonPress = 0,
buttonPressDelay = 200,
NumMenu = 0,
NumMenuLevel,
lastNumMenu[20],
lastOption[20],
currentOption,
optionCount,
buttonID,
maxOptions = 25,
player_count =0,
timerScrollSpeed,
Static_67;


/**Float**/
float
CenterDraw = 0.26f,
Menu_X = 0.758,
Title_X = 0.6350,
Cunt = 0.648;


/**Boolean**/
bool
PressX = false,
rightPress = false,
leftPress = false,
fastRPress = false,
fastLPress = false,
WhiteColor,
WhiteColor_toggle,
SelectedItem,
testT;

/**Strings**/
char* InfoText;
char* CreditText = " ";


/**Nice Stuff**/
bool init;
text_info* setTextData;
bool GodMode = true;
bool NeverWanted;
bool SuperRun;
bool SuperJump;
bool Forcefield;
bool Invisibility;
bool FreezePos;