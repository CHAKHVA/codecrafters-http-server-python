import socket
import sys
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


@dataclass(frozen=True)
class ServerConfig:
    """Configuration for the HTTP server."""

    host: str = "localhost"
    port: int = 4221
    buffer_size: int = 4096
    file_directory: str = ""


class HTTPStatus(Enum):
    """HTTP status codes with reason phrases."""

    OK = (200, "OK")
    CREATED = (201, "Created")
    NOT_FOUND = (404, "Not Found")
    INTERNAL_SERVER_ERROR = (500, "Internal Server Error")

    @property
    def code(self) -> int:
        """Get the HTTP status code."""
        return self.value[0]

    @property
    def phrase(self) -> str:
        """Get the HTTP reason phrase."""
        return self.value[1]


@dataclass(frozen=True)
class HTTPRequest:
    """Represents an HTTP request."""

    method: str
    path: str
    version: str
    headers: dict[str, str]
    body: str


@dataclass(frozen=True)
class HTTPResponse:
    """Represents an HTTP response."""

    status: HTTPStatus
    headers: dict[str, str]
    body: bytes | str = b""

    def to_bytes(self) -> bytes:
        """Serialize response to HTTP wire format."""
        body_bytes = (
            self.body if isinstance(self.body, bytes) else self.body.encode("utf-8")
        )

        response_lines = [f"HTTP/1.1 {self.status.code} {self.status.phrase}"]

        for name, value in self.headers.items():
            response_lines.append(f"{name}: {value}")

        response_lines.append("")
        response = "\r\n".join(response_lines).encode("utf-8")

        return response + b"\r\n" + body_bytes


def parse_request(raw_request: bytes) -> HTTPRequest | None:
    """Parse raw HTTP request bytes into HTTPRequest object."""
    try:
        raw_str = raw_request.decode("utf-8")
    except UnicodeDecodeError:
        return None

    lines = raw_str.split("\r\n")

    # Parse request line
    request_line = lines[0].split(" ")
    if len(request_line) < 3:
        return None

    method, path, version = request_line[0], request_line[1], request_line[2]

    # Parse headers
    headers = {}
    idx = 1
    while idx < len(lines) and lines[idx]:
        header_line = lines[idx]
        if ": " in header_line:
            key, value = header_line.split(": ", 1)
            headers[key.lower()] = value
        idx += 1

    # Parse body
    body = "\r\n".join(lines[idx + 1 :]) if idx < len(lines) - 1 else ""

    return HTTPRequest(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=body,
    )


def handle_root(request: HTTPRequest) -> HTTPResponse:
    """Handle GET / requests."""
    return HTTPResponse(status=HTTPStatus.OK, headers={}, body=b"")


def handle_echo(request: HTTPRequest, path_param: str) -> HTTPResponse:
    """Handle GET /echo/{str} requests."""
    body = path_param.encode("utf-8")
    headers = {
        "Content-Type": "text/plain",
        "Content-Length": str(len(body)),
    }
    return HTTPResponse(status=HTTPStatus.OK, headers=headers, body=body)


def handle_user_agent(request: HTTPRequest) -> HTTPResponse:
    """Handle GET /user-agent requests."""
    user_agent = request.headers.get("user-agent", "Unknown")
    body = user_agent.encode("utf-8")
    headers = {
        "Content-Type": "text/plain",
        "Content-Length": str(len(body)),
    }
    return HTTPResponse(status=HTTPStatus.OK, headers=headers, body=body)


def handle_file_get(filename: str, directory: Path) -> HTTPResponse:
    """Handle GET request to read a file."""
    filepath = directory / filename

    # Security: prevent directory traversal
    try:
        resolved_path = filepath.resolve()
        if not resolved_path.is_relative_to(directory.resolve()):
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")
    except (ValueError, OSError):
        return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")

    # Check if file exists
    if not resolved_path.is_file():
        return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")

    # Read file
    try:
        content = resolved_path.read_bytes()
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(content)),
        }
        return HTTPResponse(status=HTTPStatus.OK, headers=headers, body=content)
    except OSError as e:
        print(f"Error reading file: {e}")
        return HTTPResponse(
            status=HTTPStatus.INTERNAL_SERVER_ERROR, headers={}, body=b""
        )


def handle_file_post(filename: str, body: str, directory: Path) -> HTTPResponse:
    """Handle POST request to create/write a file."""
    filepath = directory / filename

    # Security: prevent directory traversal
    try:
        resolved_path = filepath.resolve()
        if not resolved_path.is_relative_to(directory.resolve()):
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")
    except (ValueError, OSError):
        return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")

    # Write file
    try:
        resolved_path.write_bytes(body.encode("utf-8"))
        return HTTPResponse(status=HTTPStatus.CREATED, headers={}, body=b"")
    except OSError as e:
        print(f"Error writing file: {e}")
        return HTTPResponse(
            status=HTTPStatus.INTERNAL_SERVER_ERROR, headers={}, body=b""
        )


def handle_files(request: HTTPRequest, filename: str, directory: Path) -> HTTPResponse:
    """Handle GET and POST /files/{filename} requests."""
    match request.method:
        case "GET":
            return handle_file_get(filename, directory)
        case "POST":
            return handle_file_post(filename, request.body, directory)
        case _:
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")


def route_request(request: HTTPRequest, file_directory: Path) -> HTTPResponse:
    """Route request to appropriate handler."""
    # Exact match routes
    if request.path == "/" and request.method == "GET":
        return handle_root(request)
    if request.path == "/user-agent" and request.method == "GET":
        return handle_user_agent(request)

    # Prefix match routes
    if request.path.startswith("/echo/") and request.method == "GET":
        path_param = request.path[6:]  # Remove "/echo/"
        return handle_echo(request, path_param)

    if request.path.startswith("/files/") and request.method in ("GET", "POST"):
        filename = request.path[7:]  # Remove "/files/"
        return handle_files(request, filename, file_directory)

    # 404 Not Found
    return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={}, body=b"")


class HTTPServer:
    """Manages server lifecycle and client connections."""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.server_socket: socket.socket | None = None

    def start(self) -> None:
        """Start the server and accept connections."""
        print(f"Starting HTTP server on {self.config.host}:{self.config.port}")

        self.server_socket = socket.create_server(
            (self.config.host, self.config.port), reuse_port=True
        )

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"Connection from {address}")

                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,),
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            self._cleanup()

    def _handle_client(self, client_socket: socket.socket) -> None:
        """Handle a single client connection."""
        try:
            with client_socket:
                data = client_socket.recv(self.config.buffer_size)
                if not data:
                    return

                request = parse_request(data)
                if not request:
                    print("Failed to parse request")
                    return

                print(f"[{request.method}] {request.path}")

                file_directory = Path(self.config.file_directory or ".")
                response = route_request(request, file_directory)
                response_bytes = response.to_bytes()
                client_socket.sendall(response_bytes)
        except Exception as e:
            print(f"Error handling client: {e}")

    def _cleanup(self) -> None:
        """Clean up server resources."""
        if self.server_socket:
            self.server_socket.close()


def parse_cli_args() -> ServerConfig:
    """Parse command-line arguments into server configuration."""
    file_directory = ""
    if len(sys.argv) > 2 and sys.argv[1] == "--directory":
        file_directory = sys.argv[2]
        print(f"Serving files from: {file_directory}")

    return ServerConfig(file_directory=file_directory)


def main() -> None:
    """Application entry point."""
    config = parse_cli_args()
    server = HTTPServer(config)
    server.start()


if __name__ == "__main__":
    main()
