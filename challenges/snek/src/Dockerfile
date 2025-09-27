FROM cybersecnatlab/challenge-jail:staging-ubuntu-noble@sha256:ac8981202c23cdfa859d97435562fe2688c628520824a6574e79ac4fda6b94e1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
	apt-get install -y libsdl2-2.0-0 libsdl2-image-2.0-0 && \
	apt-get clean
