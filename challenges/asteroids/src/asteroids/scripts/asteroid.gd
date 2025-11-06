#
# @mebeim - 2025-09-07
#
class_name Asteroid extends Area2D

enum Size {SMALL, MEDIUM, BIG}

signal exploded(a: Asteroid, split: bool)

# Body is either Line2D or Sprite2D
@onready var body = $Body
@export var size: Size
@export var direction: float = -1.0

var velocity = 0.0
var angular_velocity = 0.0
var teleport_radius = 0.0

func explode(split: bool = true) -> void:
	# Disable collisions to avoid multiple bullets concurrently exploding us
	process_mode = Node.PROCESS_MODE_DISABLED
	emit_signal("exploded", self, split)
	queue_free()

func get_body_rect() -> Rect2:
	# Body can either be a Line2D for simple asteroids or Sprite2D for special ones
	if body is Sprite2D:
		return body.get_rect()

	# Kinda insane that I have to code this manually but ok I guess.
	# NOTE: does not account for line thickness, but that's good enough.
	var res = Rect2()
	for i in range(body.get_point_count()):
		var p = body.get_point_position(i)
		res.position = res.position.min(p)
		res.size = res.size.max(p)

	res.size -= res.position
	return res

func _ready() -> void:
	if direction == -1:
		direction = randf_range(0, 2 * PI)

	rotation = randf_range(0, 2 * PI)
	angular_velocity = randf_range(0, 2 * PI / 3)

	var r = get_body_rect()
	var w = r.position.x
	var e = r.position.x + r.size.x
	var n = r.position.y
	var s = r.position.y + r.size.y
	teleport_radius = max(abs(w), abs(e), abs(n), abs(s))

func _process(delta: float) -> void:
	rotation += angular_velocity * delta
	global_position += Vector2(1, 0).rotated(direction) * velocity * delta

	if global_position.x - teleport_radius > Globals.xmax:
		global_position.x = Globals.xmin - teleport_radius
	elif global_position.x + teleport_radius < Globals.xmin:
		global_position.x = Globals.xmax + teleport_radius
	if global_position.y - teleport_radius > Globals.ymax:
		global_position.y = Globals.ymin - teleport_radius
	elif global_position.y + teleport_radius < Globals.ymin:
		global_position.y = Globals.ymax + teleport_radius

func _on_body_entered(n: Node2D) -> void:
	if n is Player:
		n.die()
