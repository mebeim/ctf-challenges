FROM cybersecnatlab/challenge-jail:ubuntu-noble@sha256:245f0de5bf5f9e9030dca9d9450672eea8d39474ea78a7902b93dff60f9060ad

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y python3 && apt-get clean

ENTRYPOINT ["/root/jailguesser.sh"]
