/**
 * @mebeim - 2025-09-07
 */
#include <cstdint>

#include "Achievement02AsteroidAnnihilator.h"

using namespace asteroids;

godot::String Achievement02AsteroidAnnihilator::get_name() const {
	return godot::String("ASTEROID ANNIHILATOR");
}

void Achievement02AsteroidAnnihilator::update_score(int _new_score) {
	if (achieved_)
		return;

	n_++;

	const auto n_str = godot::String::num_int64(n_);
	auto digest = n_str.sha1_buffer();
	if (memcmp(digest.ptr(), SHA1, digest.size()) != 0)
		return;

	digest = n_str.sha256_buffer();
	achieve(digest.ptr(), digest.size());
}
