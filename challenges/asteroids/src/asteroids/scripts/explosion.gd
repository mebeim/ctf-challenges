#
# @mebeim - 2025-09-07
#
extends GPUParticles2D

func _on_finished() -> void:
	queue_free()
