FROM cybersecnatlab/challenge-jail:debian-bookworm@sha256:2a938d5ebb52e69b259fe14a6b611195909c8d93757fa25dfb981829baa2d466

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
	apt-get install -y qemu-system-x86 socat && \
	apt-get clean
