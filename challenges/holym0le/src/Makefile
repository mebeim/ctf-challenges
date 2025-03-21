CHALL_NAME  := holym0le
ARCHIVE_DIR := $(CHALL_NAME)
ARCHIVE     := ../attachments/$(CHALL_NAME).tar.gz

$(ARCHIVE): build/disk-players.qcow2 Dockerfile docker-compose.yml run.py | ../attachments
	mkdir -p $(ARCHIVE_DIR)
	mkdir -p $(ARCHIVE_DIR)/build
	cp Dockerfile docker-compose.yml run.py $(ARCHIVE_DIR)
	cp build/disk-players.qcow2 $(ARCHIVE_DIR)/build/disk.qcow2
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)

../attachments:
	mkdir -p $@

build/disk-players.qcow2: build.py
	./build.py --kvm

clean:
	rm -rf build
