#!/bin/env python3
import time

import crcmod
import crcmod.predefined

from ofd.protocol import (DOCS_BY_NAME, DocCodes, FrameHeader, ProtocolPacker,
                          SessionHeader, String, pack_json)

TEST_DATA = b"*\x08A\n\x81\xa2\x01 9999078902013267'\x01\x14\x00\x00\x00'\x01\xfd\xbe\xa5\x0b\x01\x10\t\x99\x99\x07\x89\x02\x012g\x00\x00\x01n\xb2f\xd1\xb9\x00\x00\x01\x00\x02\x00\xfd\x0b\x00\xf9\x00\xb9\x04\x01\x00\x04\xa6\x04\x01\x00\x04\x11\x04\x10\x009999078902013267\r\x04\x14\x000000000000024136    \xfa\x03\x0c\x007802781104  \x10\x04\x04\x00\x01\x00\x00\x00\xf4\x03\x04\x00\xf0\xfe\xe5f5\x04\x06\x00!\x04$}\xe6\xf3\xf9\x03\x0c\x007704211201  &\x04\x01\x00\x03 \x04\x01\x00\x00\xea\x03\x01\x00\x00\xe9\x03\x01\x00\x00\n\x05\x04\x00@\x01\x00\x00\xb5\x04\x04\x00\r\x00\x00\x00\xbd\x04\x02\x00\x9a\x01\xa3\x04\x04\x00Dupa\xfd\x03\x05\x00Govno\x16\x04\x0b\x00           $\x04\x10\x00www.nalog.gov.ru]\x04\r\x00govno@dupa.ru\xf5\x03\n\x000128003270\xa4\x04\x03\x00002\xa5\x04\x01\x00\x04\x81\x063\xde\xd3\x11\xf3\x15\x00\x00"

TASKCOM_CONTINER_ACK_FD_1 = b"\x77\x00\x45\xef\x5a\x07\x01\x10\x09\x99\x99\x07\x89\x02\x01\x32\x67\x00\x00\x01\xe1\xdd\x30\x4e\x1a\x93\x21\xad\x00\x02\x00\x4d\x07\x00\x49\x00\xf9\x03\x0c\x00\x37\x37\x30\x34\x32\x31\x31\x32\x30\x31\x20\x20\x36\x04\x08\x00\x88\x06\x86\xce\x88\x30\x00\x03\x11\x04\x10\x00\x39\x39\x39\x39\x30\x37\x38\x39\x30\x32\x30\x31\x33\x32\x36\x37\x10\x04\x04\x00\x01\x00\x00\x00\xf4\x03\x04\x00\x30\xc9\xe6\x66\x2c\x04\x05\x00\xfe\x03\x01\x00\x0e\x82\x06\x36\x93\x7d\xed\x90\x6b\x00\x00"
TASKCOM_CONTINER_ACK_FD_2 = b"\x77\x00\xd5\xac\x5a\x07\x01\x10\x09\x99\x99\x07\x89\x02\x01\x32\x67\x00\x00\x02\xf0\xb1\x89\xc0\xd5\xd9\xd1\x48\x00\x02\x00\x4d\x07\x00\x49\x00\xf9\x03\x0c\x00\x37\x37\x30\x34\x32\x31\x31\x32\x30\x31\x20\x20\x36\x04\x08\x00\x88\x06\x81\x96\xdc\x3c\x00\x03\x11\x04\x10\x00\x39\x39\x39\x39\x30\x37\x38\x39\x30\x32\x30\x31\x33\x32\x36\x37\x10\x04\x04\x00\x02\x00\x00\x00\xf4\x03\x04\x00\x1f\xd2\xe6\x66\x2c\x04\x05\x00\xfe\x03\x01\x00\x00\x82\x06\xe1\x97\x19\xdc\x04\x53\x00\x00"
MYOFD_CONTINER_ACK_FD_1 = b"\x5f\x00\xf9\x66\xa5\x07\x01\x10\x09\x99\x99\x07\x89\x02\x01\x32\x67\x31\x00\x00\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x30\x07\x00\x3b\x00\xf9\x03\x0a\x00\x37\x37\x30\x34\x32\x31\x31\x32\x30\x31\x11\x04\x10\x00\x39\x39\x39\x39\x30\x37\x38\x39\x30\x32\x30\x31\x33\x32\x36\x37\x10\x04\x04\x00\x01\x00\x00\x00\xf4\x03\x04\x00\x14\xc9\xe6\x66\x2c\x04\x05\x00\xfe\x03\x01\x00\x00"


def decode_data(data: bytes):
    HEADER_LEN = 32
    h = FrameHeader.unpack_from(data[:HEADER_LEN])
    print('-' * 30)
    print(f"raw[{len(data)}]: {data}")
    print(h)
    r = ProtocolPacker.unpack_container_message(data[HEADER_LEN:], b'0')[0]
    print(r)
    print('-' * 30, end="\n\n")


def sesion_parsing():
    session_raw = TEST_DATA[:SessionHeader.STRUCT.size]
    session = SessionHeader.unpack_from(session_raw)
    print(session)
    container_raw = TEST_DATA[SessionHeader.STRUCT.size:]
    header_raw, message_raw = container_raw[:FrameHeader.STRUCT.
                                            size], container_raw[FrameHeader.
                                                                 STRUCT.size:]
    header = FrameHeader.unpack_from(header_raw)
    header.recalculate_crc(message_raw)
    print(header)
    msg, _tlv = ProtocolPacker.unpack_container_message(message_raw, b'0')
    # print(tlv)
    print(msg)


def ack_parsing():
    decode_data(TASKCOM_CONTINER_ACK_FD_1)
    decode_data(TASKCOM_CONTINER_ACK_FD_2)
    decode_data(MYOFD_CONTINER_ACK_FD_1)


def crc_calc():
    correct_crc16 = 0xef45
    crc16_ccitt = crcmod.predefined.mkPredefinedCrcFun('crc-ccitt-false')
    calculated = crc16_ccitt(TASKCOM_CONTINER_ACK_FD_1[:2] +
                             TASKCOM_CONTINER_ACK_FD_1[4:])
    print(f"{correct_crc16=:04x} = {calculated=:04x}")


def ack_build():
    message = {
        'operatorAck': {
            'ofdInn': '7704358518',  # ИНН Яндекс.ОФД
            'fiscalDriveNumber': str(9999078902013267),
            'fiscalDocumentNumber': 2,
            'dateTime': int(time.time()),
            'messageToFn': {
                'ofdResponseCode': 0
            },  # код ответа 0 при успешном получении документа
            # Теги ФПО и ФПП не указаны, т.к. должны быть добавлены реальным шифровальным комплексом
            '<unknown-1078>': b'\x88\x06\x81\x96\xdc<\x00\x03',
            'fiscalSign': 1,
        }
    }
    message_raw = pack_json(message, docs=DOCS_BY_NAME)
    print(message_raw)
    r = ProtocolPacker.unpack_container_message(message_raw, b'0')[0]
    print(r)
    h = FrameHeader(length=FrameHeader.STRUCT.size + len(message_raw),
                    crc=0,
                    doctype=DocCodes.OPERATOR_ACK,
                    devnum=b'\x99\x99\x07\x89\x02\x012g',
                    docnum=int(1).to_bytes(3, 'big'),
                    extra1=b'\x10\t',
                    extra2=String.pack('0'.rjust(12, "0")))
    h.recalculate_crc(message_raw)
    print(h)
    container_raw = h.pack() + message_raw
    print(container_raw)


def test():
    # sesion_parsing()
    ack_build()
    ack_parsing()
    # crc_calc()


if __name__ == "__main__":
    test()
