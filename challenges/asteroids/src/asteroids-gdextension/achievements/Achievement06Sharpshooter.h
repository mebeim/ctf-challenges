/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement06Sharpshooter_params.h"

#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement06Sharpshooter : public Achievement {
	GDCLASS(Achievement06Sharpshooter, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr uint8_t CTX[] = SCORE_HARD_CTX;
	static constexpr uint8_t SHA1[] = SCORE_HARD_SHA1;
	int deltas_[SCORE_HARD_N_DELTAS] = {0};
	int score_ = 0;
	size_t index_ = 0;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void update_score(int new_score) override;
};

}
