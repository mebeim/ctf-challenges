#
# @mebeim - 2025-09-07
#
extends Node

@export var xmin: float
@export var xmax: float
@export var ymin: float
@export var ymax: float

func _ready() -> void:
	# Don't have access to get_viewport_rect() here... but this should work out
	# just fine I guess.
	var viewport = get_viewport().get_visible_rect()
	xmin = viewport.position.x
	xmax = xmin + viewport.size.x
	ymin = viewport.position.y
	ymax = ymin + viewport.size.y
