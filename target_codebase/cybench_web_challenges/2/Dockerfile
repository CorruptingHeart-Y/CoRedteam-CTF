FROM golang:1.22-alpine3.18

WORKDIR /challenge/

COPY ./challenge/ /challenge/

COPY ./flag.txt /flag.txt

RUN go mod download -x \
 && go install github.com/air-verse/air@v1.52.3 \
 && go install github.com/a-h/templ/cmd/templ@v0.2.543

EXPOSE 1337
EXPOSE 50045

COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
