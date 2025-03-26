# Json2Protobuf Proxy

## Overview

Json2Protobuf is a lightweight proxy service that enables seamless JSON to Protocol Buffers conversion for HTTP requests and responses. It allows you to dynamically convert between JSON and Protobuf message formats without modifying your existing services.

## Features

- Convert JSON to Protocol Buffers for request payloads
- Optional conversion of upstream service responses back to JSON
- Flexible message type specification
- Support for GET, POST, and other HTTP methods
- Detailed error reporting
- Configurable logging

## Prerequisites

- Go 1.16+
- Protocol Buffer .proto files defining your message types

## Installation

```bash
go install github.com/sashahilton00/json2protobuf@latest
```

## Usage

```bash
json2protobuf --proto-dir=/path/to/proto/definitions [options]
```

### Options

- `--proto-dir`: Directory containing .proto files (required)
- `--addr`: Listening address (default: localhost)
- `--port`: Listening port (default: 3000)
- `--log-level`: Logging level (debug, info, warn, error)

## Request Headers

- `X-J2P-Destination-Host`: Target upstream service URL (required)
- `X-J2P-Method-Type`: Override HTTP method for upstream request
- `X-J2P-Request-Message-Type`: Protobuf message type for request payload
- `X-J2P-Response-Message-Type`: Protobuf message type for response conversion

## Examples

### GET Request (No Body)

```bash
curl http://localhost:3000/users \
  -H "X-J2P-Destination-Host=user-service.example.com" \
  -H "X-J2P-Response-Message-Type=UserList"
```

### POST Request with JSON to Protobuf Conversion

```bash
curl http://localhost:3000/users \
  -X POST \
  -H "X-J2P-Destination-Host=user-service.example.com" \
  -H "X-J2P-Request-Message-Type=CreateUserRequest" \
  -H "X-J2P-Response-Message-Type=User" \
  -d '{"username": "johndoe", "email": "john@example.com"}'
```

## Error Handling

When conversion fails, the proxy returns a JSON error response with:
- Error description
- Detailed message
- Problematic field (if applicable)

## Logging

Logs are color-coded and include request/response details at the specified log level.
