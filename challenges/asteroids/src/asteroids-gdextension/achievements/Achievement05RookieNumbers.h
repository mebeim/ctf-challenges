/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement05RookieNumbers_params.h"

#include <godot_cpp/classes/input_event.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement05RookieNumbers : public Achievement {
	GDCLASS(Achievement05RookieNumbers, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr int TARGET = SCORE_EASY_TARGET;
	static constexpr uint8_t KEY[] = SCORE_EASY_KEY;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void update_score(int new_score) override;
};

}
