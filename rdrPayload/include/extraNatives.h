void SET_TEXT_JUSTIFICATON(int type) {
	setTextData->justification = type;
}
void SET_TEXT_FONT(int fontId) {
	setTextData->font = fontId;
}
void SET_TEXT_WRAP(float start, float end) {
	setTextData->wrap_start = start;
	setTextData->wrap_end = end;
}
void SET_TEXT_SCALE_s(float scale, float scale2) {
	setTextData->text_scale = scale;
	setTextData->text_scale2 = scale2;
}
void SET_TEXT_COLOR_s(int r, int g, int b, int a) {
	fcolor fontColor;
	fontColor.r = r;
	fontColor.g = g;
	fontColor.b = b;
	fontColor.a = a;
	setTextData->color = fontColor;
}