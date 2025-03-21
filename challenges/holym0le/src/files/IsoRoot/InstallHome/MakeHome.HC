Cd(__DIR__);

// If these are not present in /Home, it uses the version in the root dir. You
// can make your own, modified, version of these files in your /Home directory.
#include "~/HomeLocalize"

// Extra utilities
#include "/Adam/Opt/Boot/MakeBoot"
#include "/Adam/Opt/Utils/MakeUtils"

// Enable auto-complete
#include "/Adam/AutoComplete/ACInit"

U0 ACInitSpawn() {
	Silent;
	ACInit("/*;!*/Bible.TXT*");
	Silent(OFF);
}

// Run ACInit in own thread to prevent boot hang
Spawn(&ACInitSpawn);

// Misc helper functions
U0 AutoHome() {
	MountAuto;
	Cdd("C:/Home");
}

#include "~/HomeWrappers"
MapFileLoad("::/Kernel/Kernel");
MapFileLoad("::/Compiler/Compiler");
#include "~/HomeKeyPlugIns"
#include "~/HomeSys"
Cd("..");
