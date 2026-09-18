# Plain HTTP 1.1 upstream

APIcast --> upstream plain HTTP 1.1 upstream

APIcast configured with plain HTTP 1.1 upstream server equipped with traffic rely agent (socat)

## Run the gateway

Running local `apicast-test` docker image

```sh
make gateway
```

Running custom apicast image

```sh
make gateway IMAGE_NAME=quay.io/3scale/apicast:latest
```

Traffic between apicast and upstream can be inspected looking at logs from `example.com` service

```
docker compose -p plain-http-upstream logs -f example.com
```

Traffic between apicast and backend can be inspected looking at logs from `backend` service

```
docker compose -p plain-http-upstream logs -f backend
```

## Testing

`GET` request

```sh
curl --resolve get.example.com:8080:127.0.0.1 -v "http://get.example.com:8080/?user_key=123"
```

`POST` request

```sh
curl --resolve post.example.com:8080:127.0.0.1 -v -X POST "http://post.example.com:8080/?user_key=123"
```

## Clean env

```sh
make clean
```

## Echo API

Using EchoAPI `quay.io/kuadrant/authorino-examples:talker-api` docker image.

Based on Ruby's [rack](https://github.com/rack/rack) / [rackup](https://github.com/rack/rackup/blob/main/lib/rackup.rb) 
HTTP server framework uses [WebRick](https://github.com/ruby/webrick) server engine.

Github: https://github.com/Kuadrant/authorino-examples/tree/main/talker-api
