/**
 * @mebeim 2024-04-14
 *
 * Adapted from TinkerOS's DoDistro.HC
 */

Bool MakeISO(U8 *_out_iso_filename) {
	U8 *out_iso_filename = FileNameAbs(_out_iso_filename);
	Bool res = TRUE;
	I64 copy_ok = 0;

	if (!DrvIsWritable) {
		PrintErr("Drive not writeable!\n");
		return -1;
	}

	DelTree("/Distro");
	Del(out_iso_filename);

	// Install CD bootloader
	// This goes as input to BootDVDIns, which is interactive
	In("TB\nScale2Mem(2048,0x40000)\nT1\n\n\n\n");
	BootDVDIns;

	// Copy over our installer and files to install onto final disc
	copy_ok += CopyTree("/IsoRoot", "/Distro") > 0;

	// Copy needed root-level files
	copy_ok += Copy("/HomeKeyPlugIns.HC.Z", "/Distro") >= 0;
	copy_ok += Copy("/HomeLocalize.HC.Z"  , "/Distro") >= 0;
	copy_ok += Copy("/HomeSys.HC.Z"       , "/Distro") >= 0;
	copy_ok += Copy("/HomeWrappers.HC.Z"  , "/Distro") >= 0;
	copy_ok += Copy("/MakeHome.HC.Z"      , "/Distro") >= 0;
	copy_ok += Copy("/PersonalNotes.DD.Z" , "/Distro") >= 0;
	copy_ok += Copy("/PersonalMenu.DD.Z"  , "/Distro") >= 0;
	copy_ok += Copy("/StartOS.HC.Z"       , "/Distro") >= 0;

	// Copy system files
	copy_ok += CopyTree(BOOT_DIR   , "/Distro" BOOT_DIR) > 0;
	copy_ok += CopyTree("/Adam"    , "/Distro/Adam"    ) > 0;
	copy_ok += CopyTree("/Compiler", "/Distro/Compiler") > 0;
	copy_ok += CopyTree("/Doc"     , "/Distro/Doc"     ) > 0;
	copy_ok += CopyTree("/Home"    , "/Distro/Home"    ) > 0;
	copy_ok += CopyTree("/Kernel"  , "/Distro/Kernel"  ) > 0;

	// Only keep Bible and Tour from /Misc
	copy_ok += DirMk("/Distro/Misc");Print("17: %d\n", copy_ok) >= 0;
	copy_ok += CopyTree("/Misc/Tour", "/Distro/Misc/Tour") > 0;
	copy_ok += Copy("/Misc/Bible.TXT.Z", "/Distro/Misc") >= 0;

	// Delete dictionary to save space
	Del("/Distro/Adam/AutoComplete/ACDefs.DATA");

	// Remove some unneeded files
	Del("/Distro/Home/DoDistro.HC.Z");

	if (copy_ok < 18) {
		PrintErr("Failed to copy some files: %d/18\n", copy_ok);
		res = FALSE;
		goto out;
	}

	RedSeaISO(out_iso_filename, "/Distro", "/Distro" BOOT_DIR_KERNEL_BIN_C);

	// RedSeaISO returns a size so there isn't a nice way to check for error
	if (!FileFind(out_iso_filename)) {
		PrintErr("RedSeaISO failed!\n");
		res = FALSE;
	}

out:
	Free(out_iso_filename);
	return res;
}

U0 IAmDone() {
	"$GREEN$$BK,1$All done!$BK,0$$FG$\n";

	// Signal QEMU that we are done through COM1
	while (1) {
		while ((InU8(0x3f8 + 5) & 0x20) == 0)
			Yield;

		OutU8(0x3f8, 'X');
		Yield;
	}
}

U0 Go() {
	"$BK,1$Hello from custom ISO builder!$BK,0$\n";
	DocBottom;

	if (!MakeISO("/Distro.ISO.C")) {
		"$RED$Error during ISO build!$FG$\n";
		return;
	}

	"$GREEN$ISO created at ::/Distro.ISO.C$FG$\n";
	IAmDone;
}

Go;
