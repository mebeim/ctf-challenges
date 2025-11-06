/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement03InterstellarCheater_params.h"

#include <godot_cpp/classes/input_event.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement03InterstellarCheater : public Achievement {
	GDCLASS(Achievement03InterstellarCheater, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr char CODE[] = CHEAT_CODE_EASY_CODE;
	static constexpr uint8_t KEY[] = CHEAT_CODE_EASY_KEY;
	unsigned index_ = 0;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void _input(const godot::Ref<godot::InputEvent> &p_event) override;
};

}
