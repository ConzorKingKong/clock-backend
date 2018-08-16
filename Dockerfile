FROM golang
ARG SECRET
ARG MONGODB_URI
ADD main.go .
RUN go get github.com/gorilla/sessions
RUN go get golang.org/x/crypto/bcrypt
RUN go get github.com/globalsign/mgo
ENV SECRET=${SECRET}
ENV MONGODB_URI=${MONGODB_URI}
RUN go build main.go
EXPOSE 3000
CMD ["./main"]
