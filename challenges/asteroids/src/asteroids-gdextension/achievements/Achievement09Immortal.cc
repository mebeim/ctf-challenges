/**
 * @mebeim - 2025-09-07
 */
#include <cstdint>

#include "Achievement09Immortal.h"

using namespace asteroids;

godot::String Achievement09Immortal::get_name() const {
	return godot::String("IMMORTAL");
}

void Achievement09Immortal::_physics_process(double delta) {
	if (achieved_)
		return;

	elapsed_time_ += delta;

	const auto time_str = godot::String::num_int64((int64_t)elapsed_time_);
	auto digest = time_str.sha1_buffer();
	if (memcmp(digest.ptr(), SHA1, digest.size()) != 0)
		return;

	digest = time_str.sha256_buffer();
	achieve(digest.ptr(), digest.size());
}
