FROM cybersecnatlab/socaz:alpine-3.19@sha256:5f1bcb7564a8fc40fd648010badb35fa98c43cb6f8ea2f8d781633a20bbe5ae1

RUN echo 'https://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories
RUN apk add pypy3

RUN echo 'space{0n3_b17_1s_4ll_17_74k3s...}' > /flag && chmod 444 /flag
COPY app.py /app.py

CMD [ "socaz", "--bind", "1337", "--uid", "65534", "--gid", "65534", \
	"--stderr", "--clear-env", "--keep-env", "PATH,USER", \
	"--", "timeout", "-k", "61", "60", "/app.py" ]
