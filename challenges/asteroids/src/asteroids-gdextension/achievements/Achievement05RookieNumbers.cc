/**
 * @mebeim - 2025-09-07
 */
#include <cstdint>

#include "Achievement05RookieNumbers.h"

using namespace asteroids;

godot::String Achievement05RookieNumbers::get_name() const {
	return godot::String("ROOKIE NUMBERS");
}

void Achievement05RookieNumbers::update_score(int new_score) {
	if (achieved_)
		return;

	if (new_score < TARGET)
		return;

	achieve(KEY, sizeof(KEY));
}
