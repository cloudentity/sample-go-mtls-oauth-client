FROM golang:1.17-alpine 

RUN mkdir /app

WORKDIR /app

COPY go.mod ./
COPY go.mod ./

RUN go mod download 

COPY . .

RUN go build -o /client

EXPOSE 18888

CMD [ "/client" ]