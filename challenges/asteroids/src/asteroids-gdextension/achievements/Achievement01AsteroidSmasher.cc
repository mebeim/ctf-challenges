/**
 * @mebeim - 2025-09-07
 */
#include <cstdint>

#include "Achievement01AsteroidSmasher.h"

using namespace asteroids;

godot::String Achievement01AsteroidSmasher::get_name() const {
	return godot::String("ASTEROID SMASHER");
}

void Achievement01AsteroidSmasher::update_score(int _new_score) {
	if (achieved_)
		return;

	if (++n_ < TARGET)
		return;

	achieve(KEY, sizeof(KEY));
}
