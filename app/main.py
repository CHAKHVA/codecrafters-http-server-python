import socket  # noqa: F401


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this to pass the first stage

    server_socket = socket.create_server(("localhost", 4221), reuse_port=True)
    sock, _ = server_socket.accept()  # wait for client
    with sock:
        data = sock.recv(1024)
        request = data.decode()

        path = request.split(" ")[1]
        if path == "/":
            response = "HTTP/1.1 200 OK\r\n"
        else:
            response = "HTTP/1.1 404 Not Found\r\n"

        sock.sendall(response.encode())


if __name__ == "__main__":
    main()
