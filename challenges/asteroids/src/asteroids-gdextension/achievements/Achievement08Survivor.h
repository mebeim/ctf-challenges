/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement08Survivor_params.h"

#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement08Survivor : public Achievement {
	GDCLASS(Achievement08Survivor, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr uint8_t SHA1[] = TIME_EASY_SHA1;
	double elapsed_time_ = 0;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void _physics_process(double delta) override;
};

}
