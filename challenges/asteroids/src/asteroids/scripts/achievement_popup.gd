extends Node2D

@onready var achievement_name = $Name:
	set(val):
		achievement_name.text = val

func _ready() -> void:
	scale = Vector2(0.1, 0.1)
	modulate.a = 0.0

	var t = create_tween()
	t.tween_property(self, "scale", Vector2(1, 1), 1.0).set_trans(Tween.TRANS_CUBIC).set_ease(Tween.EASE_OUT)
	t.parallel().tween_property(self, "modulate:a", 1.0, 1.0).set_trans(Tween.TRANS_CUBIC).set_ease(Tween.EASE_OUT)
	t.parallel().tween_property(self, "modulate:a", 0.0, 1.0).set_delay(1.5).set_trans(Tween.TRANS_CUBIC).set_ease(Tween.EASE_IN)
	t.parallel().tween_property(self, "scale", Vector2(2.0, 2.0), 1.0).set_delay(1.5).set_trans(Tween.TRANS_CUBIC).set_ease(Tween.EASE_IN)
	t.tween_callback(queue_free)
