import socket
from dataclasses import dataclass


@dataclass
class HTTPRequest:
    """Represents a parsed HTTP request."""

    method: str
    path: str
    version: str
    headers: dict[str, str]
    body: str


def parse_request(raw_request: str) -> HTTPRequest | None:
    """Parse raw HTTP request into structured data."""
    lines = raw_request.split("\r\n")

    request_line = lines[0].split(" ")
    if len(request_line) < 3:
        return None

    method, path, version = request_line[0], request_line[1], request_line[2]

    headers = {}
    idx = 1
    while idx < len(lines) and lines[idx]:
        header_line = lines[idx]
        if ": " in header_line:
            key, value = header_line.split(": ", 1)
            headers[key.lower()] = value
        idx += 1

    body = "\r\n".join(lines[idx + 1 :]) if idx < len(lines) - 1 else ""

    return HTTPRequest(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=body,
    )


def build_response(
    status_code: int,
    status_text: str,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> str:
    """Build HTTP response string."""
    response_lines = [f"HTTP/1.1 {status_code} {status_text}"]

    if headers:
        for name, value in headers.items():
            response_lines.append(f"{name}: {value}")

    response_lines.append("")
    response_lines.append(body)

    return "\r\n".join(response_lines)


def handle_root() -> str:
    """Handle requests to /"""
    return build_response(200, "OK")


def handle_echo(path_parts: list[str]) -> str:
    """Handle requests to /echo/{str}"""
    if len(path_parts) > 2:
        echo_string = path_parts[2]
        headers = {
            "Content-Type": "text/plain",
            "Content-Length": str(len(echo_string)),
        }
        return build_response(200, "OK", headers, echo_string)
    return build_response(404, "Not Found")


def handle_not_found() -> str:
    """Handle 404 responses."""
    return build_response(404, "Not Found")


def route_request(request: HTTPRequest) -> str:
    """Route request to appropriate handler."""
    path = request.path
    path_parts = path.split("/")

    if path == "/":
        return handle_root()

    if len(path_parts) > 1 and path_parts[1] == "echo":
        return handle_echo(path_parts)

    return handle_not_found()


def handle_client(client_socket: socket.socket):
    """Handle a single client connection."""
    try:
        with client_socket:
            data = client_socket.recv(4096)
            if not data:
                return

            raw_request = data.decode("utf-8")
            request = parse_request(raw_request)

            if not request:
                return

            print(f"[{request.method}] {request.path}")
            print(f"Headers: {request.headers}")

            response = route_request(request)
            client_socket.sendall(response.encode("utf-8"))
    except Exception as e:
        print(f"Error handling client: {e}")


def main():
    print("Starting HTTP server on localhost:4221")

    server_socket = socket.create_server(("localhost", 4221), reuse_port=True)

    try:
        while True:
            client_socket, address = server_socket.accept()
            print(f"Connection from {address}")
            handle_client(client_socket)
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
