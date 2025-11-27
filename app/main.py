import socket  # noqa: F401


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this to pass the first stage

    server_socket = socket.create_server(("localhost", 4221), reuse_port=True)
    sock, _ = server_socket.accept()
    with sock:
        data = sock.recv(1024)
        request = data.decode()

        path = request.split(" ")[1]
        path_chunks = path.split("/")
        print(path_chunks)
        if path == "/":
            response = "HTTP/1.1 200 OK\r\n\r\n"
        elif path_chunks[1] == "echo" and len(path_chunks) > 1:
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}".format(
                len(path_chunks[2]), path_chunks[2]
            )
        else:
            response = "HTTP/1.1 404 Not Found\r\n\r\n"

        sock.sendall(response.encode())


if __name__ == "__main__":
    main()
