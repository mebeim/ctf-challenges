/**
 * @mebeim - 2025-09-07
 */
#include <cstdint>

#include "Achievement06Sharpshooter.h"

using namespace asteroids;

godot::String Achievement06Sharpshooter::get_name() const {
	return godot::String("SHARP SHOOTER");
}

void Achievement06Sharpshooter::update_score(int new_score) {
	if (achieved_)
		return;

	deltas_[index_] = new_score - score_;
	index_ = (index_ + 1) % SCORE_HARD_N_DELTAS;
	score_ = new_score;

	godot::String deltas_str = "[";
	for (size_t i = 0; i < SCORE_HARD_N_DELTAS; i++) {
		deltas_str += godot::String::num_int64(deltas_[(index_ + i) % SCORE_HARD_N_DELTAS]);
		if (i < SCORE_HARD_N_DELTAS - 1)
			deltas_str += ", ";
	}
	deltas_str += "]";

	char value[sizeof(CTX) + 1];
	value[sizeof(value) - 1] = '\0';

	auto digest = deltas_str.sha1_buffer();
	if (memcmp(digest.ptr(), SHA1, digest.size()) != 0)
		return;

	digest = deltas_str.sha256_buffer();
	achieve(digest.ptr(), digest.size());
}
