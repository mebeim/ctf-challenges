/**
 * @mebeim 2024-04-14
 *
 * Adapted from TinkerOS's OSInstall.HC
 */

#define DRV_WAIT_TIMEOUT 30000
#define DRV_PART_TIMEOUT 60000

Bool CopyToDrive(U8 *src, U8 letter, U8 *dst_abs) {
	Bool res;
	U8 *dst;

	if (dst_abs[0] != '/') {
		PrintErr("Invalid dst_abs \"%s\", must start with '/'\n", dst_abs);
		return FALSE;
	}

	dst = MStrPrint("%C:%s", letter, dst_abs);

	"Copy %s -> %s...", src, dst;
	Silent(TRUE);
	res = Copy(src, dst);
	Silent(FALSE);

	if (res) "ok\n";
	else "ERR\n";

	Free(dst);
	return res;
}

I64 CopyTreeToDrive(U8 *src, U8 letter, U8 *dst_abs) {
	I64 res;
	U8 *dst;

	if (dst_abs[0] != '/') {
		PrintErr("Invalid dst_abs \"%s\", must start with '/'\n", dst_abs);
		return FALSE;
	}

	dst = MStrPrint("%C:%s", letter, dst_abs);

	"CopyTree %s -> %s... ", src, dst;
	Silent(TRUE);
	res = CopyTree(src, dst);
	Silent(FALSE);

	if (res) "ok (%d)\n", res;
	else "ERR\n";

	Free(dst);
	return res;
}

Bool DirMkDrive(U8 letter, U8 *path_abs, I64 entry_cnt=0) {
	Bool res;
	U8 *path;

	if (path_abs[0] != '/') {
		PrintErr("Invalid path_abs \"%s\", must start with '/'\n", path_abs);
		return FALSE;
	}

	path = MStrPrint("%C:%s", letter, path_abs);

	"DirMk %s... ", path;
	Silent(TRUE);
	res = DirMk(path, entry_cnt);
	Silent(FALSE);

	if (res) "ok\n";
	else "ERR\n";

	Free(path);
	return res;
}

I64 InstallDrv(U8 letter) {
	CDirEntry *install_home, *cur;
	Bool ready, old_silent;
	U8 *ready_dir_path;
	I64 elapsed = 0, copy_ok = 0;

	ready_dir_path = MStrPrint("%C:/Ready", letter);
	old_silent = Silent;
	ready = FALSE;

	while (!ready && elapsed <= DRV_WAIT_TIMEOUT) {
		try {
			DirMk(ready_dir_path);
			Sleep(1);

			if (IsDir(ready_dir_path)) {
				Sleep(1);
				DelTree(ready_dir_path);
				ready = TRUE;
			}
		} catch {
			Fs->catch_except = TRUE;
		}

		Sleep(100);
		elapsed += 100;
	}

	Silent(old_silent);
	Free(ready_dir_path);

	if (elapsed > DRV_WAIT_TIMEOUT) {
		PrintErr("Failed to write to drive %C, install cannot continue!\n", letter);
		return -1;
	}

	copy_ok += CopyToDrive("::/*.DD.Z" , letter, "/");
	copy_ok += CopyToDrive("::/*.HC.Z" , letter, "/");
	copy_ok += CopyTreeToDrive("::/0000Boot", letter, "/0000Boot") > 0;
	copy_ok += CopyTreeToDrive("::/Adam"    , letter, "/Adam"    ) > 0;
	copy_ok += CopyTreeToDrive("::/Compiler", letter, "/Compiler") > 0;
	copy_ok += CopyTreeToDrive("::/Doc"     , letter, "/Doc"     ) > 0;
	copy_ok += CopyTreeToDrive("::/Kernel"  , letter, "/Kernel"  ) > 0;
	copy_ok += CopyTreeToDrive("::/Misc"    , letter, "/Misc"    ) > 0;

	if (copy_ok < 8) {
		PrintErr("Failed to copy some files: %d\n", copy_ok);
		return -1;
	}

	install_home = FilesFind("::/InstallHome/*", FUF_JUST_FILES);
	if (!install_home) {
		PrintErr("Failed to list InstallHome!\n");
		return -1;
	}

	// Ensure flag is present
	if (!FilesFind("::/InstallHome/Flag.TXT", FUF_JUST_FILES)) {
		PrintErr("Flag.TXT not present in InstallHome!\n");
		return -1;
	}

	DirMkDrive(letter, "/Home");

	// Actual challenge files that go into /Home: iterate and compress all files
	// to .Z except Flag.TXT
	for (cur = install_home; cur; cur = cur->next) {
		U8 *src = MStrPrint("::/InstallHome/%s", cur->name);
		U8 *dst;

		if (IsDotZ(cur->name) || !StrCmp(cur->name, "Flag.TXT"))
			dst = MStrPrint("/Home/%s", cur->name);
		else
			dst = MStrPrint("/Home/%s.Z", cur->name);

		if (!CopyToDrive(src, letter, dst)) {
			PrintErr("Failed to copy %s\n", src);
			Free(dst);
			Free(src);
			return -1;
		}

		Free(dst);
		Free(src);
	}

	DirEntryDel(install_home);

	return 0;
}

Bool VMPrtDsk(CTask *task, CATARep *ata_drv) {
	if (!ata_drv)
		return FALSE;

	XTalkWait(task,"DskPrt(,1.0);\nC\np%d\nY",ata_drv->num);
	return TRUE;
}

I64 VMInstallDrv(CTask *task, U8 letter, CATARep *ata_drv, CATARep *atapi_drv) {
	I64 res = InstallDrv(letter);
	if (res < 0)
		return res;

	XTalkWait(task, "BootHDIns('%C');\n\nB\n0x20000\n", letter);

	if (ata_drv)
		XTalkWait(task, "C\np%d\n", ata_drv->num);

	if (atapi_drv)
		XTalkWait(task, "Tp%d\n", atapi_drv->num);

	XTalkWait(task,"\n\n");
	XTalkWait(task, "%s", "Resolution\n640\n480\nN\n");
	XTalkWait(task, "\n");

	return 0;
}

I64 DoInstall() {
	CATARep *head = NULL, *ata_drv = NULL, *atapi_drv = NULL;
	CTask *task = User;
	I64 res = 0;

	TaskWait(task);

	task->border_src  = BDS_CONST;
	task->border_attr = LTGRAY << 4 + DrvTextAttrGet(':') & 15;
	task->text_attr   = LTGRAY << 4 + BLUE;
	task->win_inhibit = WIG_TASK_DFT - WIF_SELF_BORDER;

	WinHorz(Fs->win_left, Fs->win_right, task);
	WinVert(Fs->win_top, (Fs->win_top + Fs->win_bottom) >> 2 - 1, task);
	WinVert(task->win_bottom + 3, Fs->win_bottom);
	WinToTop(Fs);

	ATARep(FALSE, TRUE, &head);
	ATAIDDrvs(head, &ata_drv, &atapi_drv);

	if (VMPrtDsk(task, ata_drv)) {
		I64 elapsed = 0;
		while (!task->user_data && elapsed <= DRV_PART_TIMEOUT) {
			Sleep(50);
			elapsed += 50;
		}

		if (elapsed > DRV_PART_TIMEOUT) {
			PrintErr("Failed to partition drive in a timely manner!\n");
			res = -1;
			goto out;
		}

		res = VMInstallDrv(task, 'C', ata_drv, atapi_drv);
		if (res < 0)
			goto out;

		"BootMHDIns on C...\n";
		BootMHDIns('C');
	}

out:
	LinkedLstDel(head);
	WinVert(task->win_top, Fs->win_bottom);
	Kill(task);

	"Install OK\n";
	return res;
}
