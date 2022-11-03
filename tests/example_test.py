import asyncio
import contextlib
import socket

import pytest

from example.mock_ofd import handle_connection, unpack_incoming_message


def unused_tcp_port() -> int:
    """Find an unused localhost port from 1024-65535 and return it."""
    with contextlib.closing(socket.socket(type=socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

@pytest.mark.asyncio(True)
async def test_ofd_emulation():
    binary_dump = b'*\x08A\n\x81\xa2\x00\x019999078900005488\xb4\x01\x14\x00\x00\x00\xb4\x01%x\xa5\x0b\x01\x10\t\x99\x99' \
               b'\x07\x89\x00\x00T\x88\x00\x00\x01\x84\xecL\x14\xc2\x00\x00\x01\x00\x04\x01\x8a\x0b\x00\x86\x01\x11' \
               b'\x04\x10\x009999078900005488\r\x04\x14\x000000000005008570    \xfa\x03\x0c\x007702203276  \x10\x04' \
               b'\x04\x00\x01\x00\x00\x00\xf4\x03\x04\x00\x98U\xb9X5\x04\x06\x00!\x04\xaa\x10uA \x04\x01\x00\x00' \
               b'\xea\x03\x01\x00\x00\xe9\x03\x01\x00\x00U\x04\x01\x00\x01V\x04\x01\x00\x00T\x04\x01\x00\x00&\x04' \
               b'\x01\x00\x06M\x04\x01\x00\x01\xf5\x03\x0c\x00000000000002\x18\x04\x11\x00\x8e\x8e\x8e \x90\x80\x8f' \
               b'\x8a\x80\x92-\xe6\xa5\xad\xe2\xe0 \xf1\x030\x00111141 \xa3.\x8c\xae\xe1\xaa\xa2\xa0, \xe3\xab. \x8a' \
               b'\xe3\xe1\xaa\xae\xa2\xe1\xaa\xa0\xef \xa4.20\x80 \xae\xe4\xa8\xe1 \x82-202\xf9\x03\x0c' \
               b'\x007704358518  $\x04\x08\x00nalog.ru]\x04\x13\x00example@example.com\xfd\x03\n\x00\x98\xa5\xad\xad' \
               b'\xae\xad \x8a. \x16\x04\n\x00OOO TAXCOM\xa5\x04\x01\x00\x02\xb9\x04\x01\x00\x02\xa4\x04\x03\x002.0' \
               b'\xa3\x041\x00111141 \xa3.\x8c\xae\xe1\xaa\xa2\xa0, \xe3\xab. \x8a\xe3\xe1\xaa\xae\xa2\xe1\xaa\xa0' \
               b'\xef\r\n\xa4.20\x80 \xae\xe4\xa8\xe1 \x82-202\xb3\x04\x0c\x00771234567890\xc5\x04\x01\x00\x00\xb7' \
               b'\x04\x01\x00\x01\x81\x06\xa5Z\xe1\x0cMu\x00\x00'

    port = unused_tcp_port()
    print(port)
    server = await asyncio.start_server(handle_connection, port=port)
    rd, wr = await asyncio.open_connection(port=port)

    wr.write(binary_dump)
    await wr.drain()
    try:
        doc, session, header = await unpack_incoming_message(rd)
        assert 'operatorAck' in doc
        assert doc['operatorAck']['fiscalDriveNumber'] == '9999078900005488'
        assert doc['operatorAck']['fiscalDocumentNumber'] == 1
        assert doc['operatorAck']['ofdInn'] == '7704358518'
        assert doc['operatorAck']['messageToFn'] == {'ofdResponseCode': 0}
    finally:
        server.close()
