$BK,1$/* Oh, hello there! */$BK,0$

#define COM1 0x3f8

U8 *menu = "What do you want to do?\n"
	"\t  1) Read a book from the Bible\n"
	"\t  2) Look up a Bible book and verse by line\n"
	"\t  3) Choose a random Bible verse for me\n"
	"\t  4) Let God generate a passphrase for me\n"
	"\t666) Commit a sin\n"
	"> ";

U8 *goodbye = "For while we were still weak, "
	"at the right time Christ died "
	"for the ungodly.\n";

U0 Die(U8 *err=NULL) {
	if (err)
		"$RED$%s\n$FG$", err;

	Sleep(3000);
	OutU16(0x604, 0x2000);

	while (1)
		Yield();
}

Bool SerialDataReady(I64 port) {
	return (InU8(port + 5) & 1) != 0;
}

Bool SerialTransEmpty(I64 port) {
	return (InU8(port + 5) & 0x20) != 0;
}

U8 RecvChar() {
	while (!SerialDataReady(COM1))
		Yield();

	return InU8(COM1);
}

U0 SendChar(U8 c) {
	while (!SerialTransEmpty(COM1))
		Yield();

	OutU8(COM1, c);
}

U0 SendAll(U8 *buf, I64 sz) {
	while (sz--)
		SendChar(*buf++);
}

U0 SendString(U8 *s) {
	SendAll(s, StrLen(s));
}

U0 RecvLine(U8 **out, I64 sz) {
	U8 *p;

	if (sz <= 0) {
		*out = NULL;
		return;
	}

	p = *out = MAlloc(sz);
	if (p == NULL)
		return;

	while (--sz) {
		*p = RecvChar();
		if (*p == '\n')
			break;

		p++;
	}

	*p = '\0';
}

I64 RecvI64() {
	U8 *num;
	I64 res;

	RecvLine(&num, 32);
	res = Str2I64(num);
	Free(num);
	return res;
}

U0 CmdReadBook(U8 *book_name, I64 lines) {
	U8 *content, *line, *res;
	I64 sz, i;
	CDoc *doc;

	doc = DocNew();
	BibleVerse(doc, book_name, lines);
	content = DocSave(doc, &sz);
	DocDel(doc);

	if (!sz) {
		U8 *err = MStrPrint("No such book as \"%s\"!\n", book_name);
		SendString(err);
		Free(err);
		goto no_book;
	}

	res = StrNew("---\n");
	line = content;

	for (i = 1; i <= lines; i++) {
		U8 *nl = StrFirstOcc(line, "\n");
		if (!nl)
			break;

		*nl = '\0';

		U8 *tmp = res;
		res = MStrPrint("%s%2d| %s\n", res, i, line);
		Free(tmp);

		line = nl + 1;
	}

	SendString(res);
	Free(res);

no_book:
	Free(content);
}

U0 CmdLookupVerse(I64 lineno) {
	U8 *verse = BibleLine2Verse(lineno);
	if (!*verse) {
		SendString("This line does not correspond to any known verse.\n");
		return;
	}

	SendString(verse);
	SendString("\n");
	Free(verse);
}

U0 CmdRandVerse() {
	U8 *verse = NULL;

	while (!verse)
		verse = BibleLine2Verse(GetTSC() % ST_BIBLE_LINES + 1);

	SendString(verse);
	SendString("\n");
	Free(verse);
}

U0 CmdGodPassphrase(I64 words) {
	SendString("Your passphrase is: ");

	while (words--) {
		GodBitsIns(GOD_GOOD_BITS, GetTSC());
		SendString(GodWordStr());

		if (words)
			SendString("-");
	}

	SendString("\n");
}

U0 DoCommand() {
	U8 *book;
	I64 n;

	SendString(menu);
	n = RecvI64();

	if (n >= '[XX]') {
		"$RED$--- [DEBUG] ---\n$FG$";
		"$RED$Task: %s (%s)\n$FG$", Fs->task_name, Fs->task_title;

		if (n >= '[XX]' + 1)
			"$RED$Parent: %s (%s)\n$FG$", Fs->parent_task->task_name,
				Fs->parent_task->task_title;
		if (n >= '[XX]' + 2)
			"$RED$Dir: %c://%s\n$FG$", Drv2Let(), Fs->cur_dir;
		if (n >= '[XX]' + 3)
			"$RED$Window: %d %d %d %d\n$FG$", Fs->win_left,
				Fs->win_right, Fs->win_top, Fs->win_bottom;

		return;
	}

	SendString("---\n");

	switch [n] {
	case 1:
		SendString("Which book? ");
		RecvLine(&book, 150);

		SendString("How many lines? ");
		n = RecvI64();

		if (n < 1) {
			SendString("Cannot really read less than 1 line!\n");
			Free(book);
			break;
		}
		if (n > 50) {
			SendString("I'm afraid we don't have that much time!\n");
			Free(book);
			break;
		}

		CmdReadBook(book, n);
		Free(book);
		break;

	case 2:
		SendString("Which line? ");
		n = RecvI64();

		if (n < 297) {
			SendString("Line too small!\n");
			break;
		}
		if (n > ST_BIBLE_LINES) {
			SendString("Line too big!\n");
			break;
		}

		CmdLookupVerse(n);
		break;

	case 3:
		CmdRandVerse();
		break;

	case 4:
		SendString("How many words? ");
		n = RecvI64();

		if (n < 1) {
			SendString("That's not secure enough!\n");
			break;
		}
		if (n > 8) {
			SendString("You're never going to remember that!\n");
			break;
		}

		CmdGodPassphrase(n);
		break;

	case 666:
		SendString(goodbye);
		Die("Client committed a sin!");
		break;

	default:
		SendString("No such command!\n");
		break;
	}

	SendString("---\n");
}

U0 Banner() {
	CDoc *doc;
	U8 *content;
	I64 size;

	doc = DocRead("~/Banner.TXT.Z");
	content = DocSave(doc, &size);
	DocDel(doc);

	SendAll(content, size);
	Free(content);
}

U0 Challenge() {
	StrCpy(Fs->task_name, "HolyM0le!");
	Fs->title_src = TTS_TASK_NAME;

	"$GREEN$HolyM0le!\n$FG$";
	Banner();

	while (1) {
		DoCommand();
	}
}
