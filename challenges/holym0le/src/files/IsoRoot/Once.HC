/**
 * @mebeim 2024-04-14
 */

#include "::/CustomOSInstall.HC"

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
	"$BK,1$Hello from custom installer!$BK,0$\n";
	DocBottom;

	if (DoInstall() < 0) {
		"$RED$Error during install!$FG$\n";
		return;
	}

	IAmDone;
}

Go;
