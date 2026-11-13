FROM golang:1.19-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/shadow-core-go .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/shadow-core-go /shadow-core-go
EXPOSE 8081
ENTRYPOINT ["/shadow-core-go"]
