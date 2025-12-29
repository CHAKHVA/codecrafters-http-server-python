import socket
import sys
import threading
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ServerConfig:
    """Configuration for the HTTP server."""

    host: str = "localhost"
    port: int = 4221
    buffer_size: int = 4096
    file_directory: str = ""


class HTTPStatus(IntEnum):
    """HTTP status codes with reason phrases."""

    OK = 200
    CREATED = 201
    NOT_FOUND = 404
    INTERNAL_SERVER_ERROR = 500

    @property
    def reason_phrase(self) -> str:
        """Get the reason phrase for this status code."""
        return {
            200: "OK",
            201: "Created",
            404: "Not Found",
            500: "Internal Server Error",
        }[self.value]


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
    body: bytes | str = ""

    def to_bytes(self) -> bytes:
        """Serialize response to HTTP wire format."""
        # Convert body to bytes if needed
        body_bytes = (
            self.body if isinstance(self.body, bytes) else self.body.encode("utf-8")
        )

        # Build response lines
        response_lines = [f"HTTP/1.1 {self.status} {self.status.reason_phrase}"]

        # Add headers
        for name, value in self.headers.items():
            response_lines.append(f"{name}: {value}")

        # Add empty line and body
        response_lines.append("")
        response = "\r\n".join(response_lines).encode("utf-8")

        return response + b"\r\n" + body_bytes


# ============================================================================
# Request/Response Processing
# ============================================================================
class HTTPRequestParser:
    """Parse raw HTTP requests into structured data."""

    @staticmethod
    def parse(raw_request: bytes) -> HTTPRequest | None:
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


# ============================================================================
# Handler Protocol & Base Classes
# ============================================================================
class HandlerProtocol(Protocol):
    """Protocol defining the interface for request handlers."""

    def matches(self, request: HTTPRequest) -> bool:
        """Check if this handler can handle the given request."""
        ...

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        """Handle the request and return a response."""
        ...


class RouteHandler:
    """Base class for route handlers."""

    def __init__(self, pattern: str):
        self.pattern = pattern

    def matches(self, request: HTTPRequest) -> bool:
        """Default implementation: exact path match."""
        return request.path == self.pattern

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        """Handle the request. Must be overridden by subclasses."""
        raise NotImplementedError


class PathPrefixHandler(RouteHandler):
    """Handler for routes with path prefixes like /echo/* or /files/*."""

    def matches(self, request: HTTPRequest) -> bool:
        """Check if request path starts with the handler's pattern."""
        return request.path.startswith(
            self.pattern
        ) or request.path == self.pattern.rstrip("/")

    def extract_path_param(self, request: HTTPRequest) -> str | None:
        """Extract the path parameter after the prefix."""
        if not request.path.startswith(self.pattern):
            return None

        # Extract everything after the prefix
        param = request.path[len(self.pattern) :]
        return param if param else None


# ============================================================================
# Concrete Handlers
# ============================================================================
class RootHandler(RouteHandler):
    """Handle GET / requests."""

    def __init__(self):
        super().__init__("/")

    def matches(self, request: HTTPRequest) -> bool:
        return request.path == "/" and request.method == "GET"

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        return HTTPResponse(status=HTTPStatus.OK, headers={})


class EchoHandler(PathPrefixHandler):
    """Handle GET /echo/{str} requests."""

    def __init__(self):
        super().__init__("/echo/")

    def matches(self, request: HTTPRequest) -> bool:
        return request.path.startswith("/echo/") and request.method == "GET"

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        echo_str = self.extract_path_param(request)
        if not echo_str:
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

        body = echo_str.encode("utf-8")
        headers = {
            "Content-Type": "text/plain",
            "Content-Length": str(len(body)),
        }
        return HTTPResponse(status=HTTPStatus.OK, headers=headers, body=body)


class UserAgentHandler(RouteHandler):
    """Handle GET /user-agent requests."""

    def __init__(self):
        super().__init__("/user-agent")

    def matches(self, request: HTTPRequest) -> bool:
        return request.path == "/user-agent" and request.method == "GET"

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        user_agent = request.headers.get("user-agent", "Unknown")
        body = user_agent.encode("utf-8")
        headers = {
            "Content-Type": "text/plain",
            "Content-Length": str(len(body)),
        }
        return HTTPResponse(status=HTTPStatus.OK, headers=headers, body=body)


class FileHandler(PathPrefixHandler):
    """Handle GET and POST /files/{filename} requests."""

    def __init__(self, directory: Path):
        super().__init__("/files/")
        self.directory = directory

    def matches(self, request: HTTPRequest) -> bool:
        return request.path.startswith("/files/") and request.method in ("GET", "POST")

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        """Route to appropriate method handler."""
        match request.method:
            case "GET":
                return self._handle_get(request)
            case "POST":
                return self._handle_post(request)
            case _:
                return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

    def _handle_get(self, request: HTTPRequest) -> HTTPResponse:
        """Handle GET request to read a file."""
        filename = self.extract_path_param(request)
        if not filename:
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

        filepath = self.directory / filename

        # Security: prevent directory traversal
        try:
            resolved_path = filepath.resolve()
            if not resolved_path.is_relative_to(self.directory.resolve()):
                return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})
        except (ValueError, OSError):
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

        # Check if file exists
        if not resolved_path.is_file():
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

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
            return HTTPResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR, headers={})

    def _handle_post(self, request: HTTPRequest) -> HTTPResponse:
        """Handle POST request to create/write a file."""
        filename = self.extract_path_param(request)
        if not filename:
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

        filepath = self.directory / filename

        # Security: prevent directory traversal
        try:
            resolved_path = filepath.resolve()
            if not resolved_path.is_relative_to(self.directory.resolve()):
                return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})
        except (ValueError, OSError):
            return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})

        # Write file
        try:
            resolved_path.write_bytes(request.body.encode("utf-8"))
            return HTTPResponse(status=HTTPStatus.CREATED, headers={})
        except OSError as e:
            print(f"Error writing file: {e}")
            return HTTPResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR, headers={})


class NotFoundHandler:
    """Fallback handler for 404 responses."""

    def matches(self, request: HTTPRequest) -> bool:
        """Always matches - serves as catch-all."""
        return True

    def handle(self, request: HTTPRequest) -> HTTPResponse:
        """Return 404 Not Found."""
        return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})


# ============================================================================
# Router
# ============================================================================
class HTTPRouter:
    """
    Route requests to handlers.
    Implements Open/Closed Principle: open for extension, closed for modification.
    """

    def __init__(self):
        self.handlers: list[HandlerProtocol] = []

    def register(self, handler: HandlerProtocol) -> None:
        """Register a handler. Order matters - first match wins."""
        self.handlers.append(handler)

    def route(self, request: HTTPRequest) -> HTTPResponse:
        """Find the first matching handler and delegate the request."""
        for handler in self.handlers:
            if handler.matches(request):
                return handler.handle(request)

        # Should never reach here if NotFoundHandler is registered last
        return HTTPResponse(status=HTTPStatus.NOT_FOUND, headers={})


# ============================================================================
# Server
# ============================================================================
class HTTPServer:
    """Manages server lifecycle and client connections."""

    def __init__(self, config: ServerConfig, router: HTTPRouter):
        self.config = config
        self.router = router
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

                request = HTTPRequestParser.parse(data)
                if not request:
                    print("Failed to parse request")
                    return

                print(f"[{request.method}] {request.path}")

                response = self.router.route(request)
                response_bytes = response.to_bytes()
                client_socket.sendall(response_bytes)
        except Exception as e:
            print(f"Error handling client: {e}")

    def _cleanup(self) -> None:
        """Clean up server resources."""
        if self.server_socket:
            self.server_socket.close()


# ============================================================================
# Application Bootstrap
# ============================================================================
def create_app(config: ServerConfig) -> HTTPServer:
    """
    Factory function to create a configured HTTP server application.
    Implements Dependency Inversion: wires up dependencies.
    """
    router = HTTPRouter()

    # Register handlers in order (specific to general)
    # First match wins, so order matters
    router.register(RootHandler())
    router.register(EchoHandler())
    router.register(UserAgentHandler())
    router.register(FileHandler(Path(config.file_directory or ".")))
    router.register(NotFoundHandler())  # Catch-all must be last

    return HTTPServer(config, router)


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
    app = create_app(config)
    app.start()


if __name__ == "__main__":
    main()
