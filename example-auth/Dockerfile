FROM golang:1.24.1-alpine

WORKDIR /app
COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o main main.go
CMD ["./main"]