/**
 * @mebeim - 2025-09-07
 */
#include "AchievementManager.h"
#include "achievements/Achievement.h"
#include "achievements/all.h"
#include "register_types.h"

#include <gdextension_interface.h>
#include <godot_cpp/core/defs.hpp>
#include <godot_cpp/core/class_db.hpp>

using namespace asteroids;

void init_module(godot::ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE)
		return;

	GDREGISTER_RUNTIME_CLASS(AchievementManager);
	achievements_register_types();
}

extern "C" {

GDExtensionBool GDE_EXPORT asteroids_lib_achievement_manager_init(
		GDExtensionInterfaceGetProcAddress p_get_proc_address,
		const GDExtensionClassLibraryPtr p_library,
		GDExtensionInitialization *r_initialization)
{
	GDExtensionBinding::InitObject init_obj(p_get_proc_address, p_library, r_initialization);

	init_obj.register_initializer(init_module);
	init_obj.set_minimum_library_initialization_level(MODULE_INITIALIZATION_LEVEL_SCENE);

	return init_obj.init();
}

}
