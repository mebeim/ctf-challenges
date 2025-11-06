/**
 * @mebeim - 2025-09-07
 */
#include "Achievement.h"

#include <godot_cpp/core/class_db.hpp>

using namespace asteroids;

void Achievement::_bind_methods() {
	ADD_SIGNAL(godot::MethodInfo("achieved",
		godot::PropertyInfo(godot::Variant::STRING, "name"),
		godot::PropertyInfo(godot::Variant::STRING, "value")));
}
