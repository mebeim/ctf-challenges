/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement09Immortal_params.h"

#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement09Immortal : public Achievement {
	GDCLASS(Achievement09Immortal, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr uint8_t SHA1[] = TIME_HARD_SHA1;
	double elapsed_time_ = 0;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void _physics_process(double delta) override;
};

}
