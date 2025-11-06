#
# @mebeim - 2025-09-07
#
class_name Player extends CharacterBody2D

signal bullet_shot(bullet: Node)
signal died()
signal thrusters_toggled(enabled: bool)

const MAX_VELOCITY = 500
const ACCELERATION = 10

@onready var body = $SpaceshipBody
@onready var gun = $Gun
@onready var thrusters = $SpaceshipThrusters

var bullet_scene = preload("res://scenes/bullet.tscn")
var alive = true

func shoot() -> void:
	var b = bullet_scene.instantiate()
	b.global_position = gun.global_position
	b.rotation = rotation
	b.velocity = max(400, velocity.length() + 100)
	emit_signal("bullet_shot", b)

func die() -> void:
	if not alive:
		return

	alive = false
	emit_signal("died")

	body.visible = false
	thrusters.visible = false
	process_mode = Node.PROCESS_MODE_DISABLED

func _process(_delta: float) -> void:
	var mouse = get_global_mouse_position()
	var thrust = int(Input.is_action_pressed("thrust"))
	var direction = Vector2(mouse - global_position).normalized()

	velocity = velocity.move_toward(direction * MAX_VELOCITY, thrust * ACCELERATION)

	# Don't move outside viewport (can slide on the wall but will stop at corners)
	if global_position.x >= Globals.xmax:
		global_position.x = Globals.xmax
		velocity.x = min(velocity.x, 0)
	elif global_position.x <= Globals.xmin:
		global_position.x = Globals.xmin
		velocity.x = max(velocity.x, 0)
	if global_position.y >= Globals.ymax:
		global_position.y = Globals.ymax
		velocity.y = min(velocity.y, 0)
	elif global_position.y <= Globals.ymin:
		global_position.y = Globals.ymin
		velocity.y = max(velocity.y, 0)

	look_at(mouse)
	move_and_slide()

func _physics_process(_delta: float) -> void:
	if not alive:
		return

	thrusters.visible = alive and Input.is_action_pressed("thrust")

	if Input.is_action_just_pressed("shoot"):
		shoot()

	if Input.is_action_just_pressed("thrust"):
		emit_signal("thrusters_toggled", true)
	elif Input.is_action_just_released("thrust"):
		emit_signal("thrusters_toggled", false)
