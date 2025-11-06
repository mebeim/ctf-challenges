/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement07WarpSpeed_params.h"

#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement07WarpSpeed : public Achievement {
	GDCLASS(Achievement07WarpSpeed, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr double TARGET = SPEED_TARGET;
	static constexpr double TIME = SPEED_TIME;
	static constexpr uint8_t KEY[] = SPEED_KEY;
	godot::Node *player_ = nullptr;
	double elapsed_time_ = 0;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void _ready() override;
	void _physics_process(double delta) override;
};

}
