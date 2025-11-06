/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement01AsteroidSmasher_params.h"

#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement01AsteroidSmasher : public Achievement {
	GDCLASS(Achievement01AsteroidSmasher, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr uint8_t KEY[] = ASTEROIDS_EXPLODED_EASY_KEY;
	static constexpr int TARGET = ASTEROIDS_EXPLODED_EASY_N;
	unsigned n_ = 0;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void update_score(int _new_score) override;
};

}
