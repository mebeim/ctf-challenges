#!/bin/bash
#
# @mebeim - 2024-09-18
#

shopt -s nullglob

### Hint: add --debug for debugging purposes (stderr will go to docker logs)
socaz \
	--bind 1337 \
	--clear-env \
	--keep-env PATH,TIMEOUT \
	--flag-from-env FLAG \
	--timeout "$TIMEOUT" \
	--cmd /root/jailguesser.py \
	&

while :; do
	now="$(date -u +%s)"

	for f in /tmp/jailguesser*; do
		if [ "$now" -gt "${f##*.}" ]; then
			rm "$f"
		fi
	done

	sleep 5
done
