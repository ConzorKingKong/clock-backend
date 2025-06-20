FROM golang:1.23.0
WORKDIR /app
EXPOSE 3000
ARG SECRET
ARG MONGODB_URI
ADD go.mod go.sum .
RUN go mod download
ADD main.go .
RUN go build main.go
RUN rm -rf go.mod go.sum main.go
CMD ["./main"]