/**
 * @mebeim - 2025-09-07
 */
#include "all.h"

#include <godot_cpp/core/class_db.hpp>

using namespace asteroids;

void achievements_register_types() {
	GDREGISTER_RUNTIME_CLASS(Achievement);
	GDREGISTER_RUNTIME_CLASS(Achievement01AsteroidSmasher);
	GDREGISTER_RUNTIME_CLASS(Achievement02AsteroidAnnihilator);
	GDREGISTER_RUNTIME_CLASS(Achievement03InterstellarCheater);
	GDREGISTER_RUNTIME_CLASS(Achievement04InterstellarHacker);
	GDREGISTER_RUNTIME_CLASS(Achievement05RookieNumbers);
	GDREGISTER_RUNTIME_CLASS(Achievement06Sharpshooter);
	GDREGISTER_RUNTIME_CLASS(Achievement07WarpSpeed);
	GDREGISTER_RUNTIME_CLASS(Achievement08Survivor);
	GDREGISTER_RUNTIME_CLASS(Achievement09Immortal);
}
