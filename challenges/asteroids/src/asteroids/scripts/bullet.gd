#
# @mebeim - 2025-09-07
#
extends Area2D

@export var velocity = 0.0

func _process(delta):
	global_position += Vector2(1, 0).rotated(rotation) * velocity * delta

func _on_visible_on_screen_notifier_2d_screen_exited() -> void:
	queue_free()

func _on_area_entered(a: Area2D) -> void:
	if a is Asteroid:
		a.explode()
		queue_free()
