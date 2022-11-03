# coding: utf8
#
#        Copyright (C) 2017 Yandex LLC
#        http://yandex.com
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and


import array
import base64
import datetime
import decimal
import json
import os
import re
import struct

import crcmod
import crcmod.predefined
import jsonschema
from jsonschema import Draft4Validator, ValidationError

VERSION = (1, 1, 0, 'ATOL-3')

SIGNATURE = array.array('B', [42, 8, 65, 10]).tobytes().decode("utf-8")

FLK_ERROR = 14  # Ошибка форматно-логического контроля при обработке документа

JSON_VERSION = 13  # version of json format (OFD to FNS protocol) which is used to unpack document


class ProtocolError(RuntimeError):
    pass


class InvalidProtocolDocument(ProtocolError):
    def __init__(self):
        super(InvalidProtocolDocument, self).__init__('invalid document')


class Byte(object):
    """
    Represents a single-byte document item packer/unpacker.
    """
    STRUCT = struct.Struct('B')

    def __init__(self, name, desc, cardinality=None, parents=None):
        """
        Initialize a single-byte document item with the given name and description.
        :param name: name as it is encoded in Federal Tax Service.
        :param desc: description as it is specified in OFD protocol.
        :param cardinality: specifies how many times the given document item should appear in the parent document. None
               Possible values: number as a string meaning exact number, '+' meaning one or more, '*' meaning zero or
               more, None meaning that the cardinality is undefined.
        """
        self.name = name
        self.desc = desc
        self.cardinality = cardinality
        self.maxlen = self.STRUCT.size
        self.parents = parents
        self.ty = None

    def pack(self, data):
        """
        Pack the given value into a byte representation.
        :param data: a single byte value.
        :raise struct.error: if data is not an integer or it does not fit in [0; 255] range.
        :return: packed value as a bytearray.
        >>> Byte('', '').pack(42)
        b'*'
        >>> Byte('', '').pack(256)
        Traceback (most recent call last):
        ...
        struct.error: ubyte format requires 0 <= number <= 255
        >>> Byte('', '').pack('string')
        Traceback (most recent call last):
        ...
        struct.error: required argument is not an integer
        """
        return self.STRUCT.pack(data)

    def unpack(self, data):
        # for zero-length tag value
        if len(data) == 0:
            return 0
        return self.STRUCT.unpack(data)[0]


class U32(object):
    def __init__(self, name, desc, cardinality=None, parents=None):
        self.name = name
        self.desc = desc
        self.maxlen = 4,
        self.cardinality = cardinality,
        self.parents = parents
        self.ty = None

    @staticmethod
    def pack(data):
        return struct.pack('<I', data)

    @staticmethod
    def unpack(data):
        # for zero-length tag value
        if len(data) == 0:
            return 0
        return struct.unpack('<I', data)[0]


class String(object):
    def __init__(self, name, desc, maxlen, cardinality=None, parents=None, strip=False):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen
        self.parents = parents
        self.strip = strip
        self.cardinality = cardinality
        self.ty = None

    @staticmethod
    def pack(value):
        return struct.pack('{}s'.format(len(value)), value.encode('cp866'))

    def unpack(self, data):
        if len(data) == 0:
            return ''
        if len(data) > self.maxlen:
            raise ValueError('String tag {ty} actual size {actual} is greater than maximum {max}. Data: {data}'
                             .format(ty=self.ty, actual=len(data), max=self.maxlen, data=data))

        result = struct.unpack('{}s'.format(len(data)), data)[0].decode('cp866')
        if self.strip:
            result = result.strip()
        return result


class ByteArray(object):
    def __init__(self, name, desc, maxlen, parents=None):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen
        self.parents = parents
        self.ty = None

    @staticmethod
    def pack(value):
        return struct.pack('{}s'.format(len(value)), value)

    def unpack(self, data):
        if len(data) == 0:
            return ''
        if len(data) > self.maxlen:
            raise ValueError('ByteArray actual size {} is greater than maximum {}'.format(len(data), self.maxlen))
        return str(struct.unpack('{}s'.format(len(data)), data)[0])


class UnixTime(object):
    def __init__(self, name, desc, parents=None):
        self.name = name
        self.desc = desc
        self.maxlen = 4
        self.parents = parents
        self.ty = None

    @staticmethod
    def pack(time):
        return struct.pack('<I', int(time))

    @staticmethod
    def unpack(data):
        return struct.unpack('<I', data)[0]


class VLN(object):
    def __init__(self, name, desc, maxlen=8, parents=None):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen
        self.parents = parents
        self.ty = None

    def pack(self, data):
        packed = struct.pack('<Q', data)
        # Если длина полученного массива больше maxlen, то у массива будут обрезаны нули справа до maxlen,
        # т.к. они не влияют на итоговое значение числа
        if len(packed) > self.maxlen:
            trim_part = packed[self.maxlen: len(packed)]
            # Если отбрасываемая часть содержит не только нули, значит переданное число больше чем maxlen и
            # оно не может быть корректно упаковано
            if trim_part != b'\x00' * len(trim_part):
                raise ValueError('VLN cant pack {} because is greater than maximum {}'.format(data, self.maxlen))
            return packed[:self.maxlen]

        return packed

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('VLN for "{}" actual size {} is greater than maximum {}'
                             .format(self.name, len(data), self.maxlen))
        return struct.unpack('<Q', data + b'\x00' * (8 - len(data)))[0]


class FVLN(object):
    def __init__(self, name, desc, maxlen, parents=None):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen
        self.parents = parents
        self.ty = None

    def pack(self, data):
        str_data = str(data)
        point = str_data.index('.')
        prepared = int(str_data[0:point] + str_data[point + 1:])

        # первый байт, который указывает положение точки в числе относительно правого края
        point_position = len(str_data) - 1 - point
        packed = struct.pack('<bQ', point_position, prepared)

        # Если длина полученного массива больше maxlen, то у массива будут обрезаны нули справа до maxlen,
        # т.к. они не влияют на итоговое значение числа
        if len(packed) > self.maxlen:
            trim_part = packed[self.maxlen: len(packed)]
            # Если отбрасываемая часть содержит не только нули, значит переданное число больше чем maxlen и
            # оно не может быть корректно упаковано
            if trim_part != b'\x00' * len(trim_part):
                raise ValueError('FVLN cant pack {} because is greater than maximum {}'.format(data, self.maxlen))
            return packed[:self.maxlen]

        return packed

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('FVLN actual size is greater than maximum')

        pad = b'\x00' * (9 - len(data))
        pos, num = struct.unpack('<bQ', data + pad)
        d = decimal.Decimal(10) ** +pos
        q = decimal.Decimal(10) ** -pos
        return float((decimal.Decimal(num) / d).quantize(q))


class STLV(object):
    def __init__(self, name, desc, maxlen, cardinality='1', parents=None):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen
        self.cardinality = cardinality
        self.parents = parents
        self.ty = None

    @staticmethod
    def pack(data):
        return data

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('STLV actual size is greater than maximum')

        result = {}

        while len(data) > 0:
            ty, length = struct.unpack('<HH', data[:4])
            doc = self._select_tag_by_parent(ty)
            value = doc.unpack(data[4:4 + length])

            if hasattr(doc, 'cardinality'):
                if doc.cardinality in {'*', '+'}:
                    if doc.name not in result:
                        result[doc.name] = []
                    result[doc.name].append(value)
                else:
                    result[doc.name] = value
            else:
                result[doc.name] = value
            data = data[4 + length:]

        return result

    def _select_tag_by_parent(self, ty):
        """
        Найти соответствие для тега по его номеру. Если одному номеру соответствует несколько тегов, то
        выбираем нужный тег в зависимости от указанных для него номеров родительских тегов
        :param ty: номер тега, который нужно расшифровать
        :return: объект с описанием тега и правилами его расшифровки
        """
        docs = DOCUMENTS[ty]
        if not isinstance(docs, list):
            return docs

        for d in docs:
            if d.parents and self.ty in d.parents:
                return d

        # если соответствие не найдено, то кидаем ошибку - это лучше, чем расшифровать в неправильный тег
        raise ProtocolError('Cant select correct json for {} with parent {}'.format(ty, self.ty))


class SessionHeader(object):
    MAGIC_ID, PVERS_ID, PVERA_ID = range(3)
    MAGIC, = struct.unpack('<I', bytearray.fromhex('2a08410a'))
    PVERS, = struct.unpack('<H', bytearray.fromhex('81a2'))
    PVERA = {
        struct.unpack('<H', bytearray.fromhex('0001'))[0],
        struct.unpack('<H', bytearray.fromhex('0002'))[0],
        struct.unpack('<H', bytearray.fromhex('0100'))[0],
        struct.unpack('<H', bytearray.fromhex('0105'))[0],
        struct.unpack('<H', bytearray.fromhex('0110'))[0]
    }
    STRUCT = struct.Struct('<IHH16sHHH')
    MAX_LEN = 32 * 1024  # максимальная длина контейнера - 32кб
    # flags 010100:
    # 01 - client expects response to the message
    # 0 - reserved field, always 0
    # 01 - message contains container body
    # 00 - CRC code is not calculated
    SESSION_FLAGS = 0b0000000000010100

    # пустые значения флагов
    EMPTY_FLAGS = 0b0000000000000000

    INCLUDE_CONTAINER_FLAG = 0b0100  # флаг указывает, что сообщение содержит контейнер

    def __init__(self, pva, fs_id, length, flags, crc):
        self.pva = pva
        # Номер ФН.
        self.fs_id = fs_id
        self.length = length
        self.flags = flags
        self.crc = crc

    def pack(self):
        return self.STRUCT.pack(
            self.MAGIC,
            self.PVERS,
            self.pva,
            self.fs_id,
            self.length,
            self.flags,
            self.crc
        )

    @property
    def pva_hex(self):
        """Get hex string of application protocol version"""
        return struct.pack('<H', self.pva).hex()

    @classmethod
    def unpack_from(cls, data):
        if len(data) != cls.STRUCT.size:
            raise ValueError('data size must be 30')
        pack = cls.STRUCT.unpack(data)

        if pack[cls.MAGIC_ID] != cls.MAGIC:
            raise ValueError('invalid protocol signature')
        if pack[cls.PVERS_ID] != cls.PVERS:
            raise ValueError('invalid session protocol version')

        if pack[cls.PVERA_ID] not in cls.PVERA:
            raise ValueError('invalid application protocol version')

        return SessionHeader(pack[cls.PVERA_ID], *pack[cls.PVERA_ID + 1:])

    def __str__(self):
        return 'Заголовок Сообщения сеансового уровня\n' \
               '{:24}: {:#010x}\n' \
               '{:24}: {:#06x}\n' \
               '{:24}: {:#06x}\n' \
               '{:24}: {}\n' \
               '{:24}: {}\n' \
               '{:24}: {:#b}\n' \
               '{:24}: {}'.format(
                                'Сигнатура', self.MAGIC,
                                'Версия S-протокола', self.PVERS,
                                'Версия A-протокола', self.pva,
                                'Номер ФН', self.fs_id,
                                'Размер тела', self.length,
                                'Флаги', self.flags,
                                'Проверочный код (CRC)', self.crc)


class FrameHeader(object):
    MSGTYPE_ID, VERSION_ID = (2, 4)
    MSGTYPE = 0xa5
    VERSION = 1
    STRUCT = struct.Struct('<HHBBB2s8s3s12s')
    STRUCT_TINY = struct.Struct('<BBB2s8s3s12s')

    def __init__(self, length, crc, doctype, extra1, devnum, docnum, extra2):
        # Длина.
        self.length = length
        # Проверочный код.
        self.crc = crc
        # Тип сообщения протокола.
        self.msgtype = self.MSGTYPE
        # Тип фискального документа.
        self.doctype = doctype
        # Версия протокола.
        self.version = self.VERSION
        # Номер ФН.
        self.devnum = devnum
        # Номер ФД.
        self._docnum = docnum
        # Служебные данные 1.
        self.extra1 = extra1
        # Служебные данные 2.
        self.extra2 = extra2

    def pack(self):
        return self.STRUCT.pack(
            self.length,
            self.crc,
            self.MSGTYPE,
            self.doctype,
            self.version,
            self.extra1,
            self.devnum,
            self._docnum,
            self.extra2
        )

    @classmethod
    def unpack_from(cls, data):
        if len(data) != cls.STRUCT.size:
            raise ValueError('data size must be 32')
        pack = cls.STRUCT.unpack(data)

        # if pack[cls.MSGTYPE_ID] != cls.MSGTYPE:
        #     raise ValueError('invalid message type')
        if pack[cls.VERSION_ID] != cls.VERSION:
            raise ValueError('invalid protocol version')

        return FrameHeader(pack[0], pack[1], pack[3], *pack[5:])

    @classmethod
    def unpack_from_raw(cls, data, msg_type=None):
        """
        Unpack container header directly from bytearray without `length` and `CRC` fields.

        :param data: container header.
        :param msg_type: expected message type, if not None method asserts actual msg type with expected and
        throws ValueError exception if they are not equal
        :return: structured ContainerHeader.
        """
        if len(data) != cls.STRUCT_TINY.size:
            raise ValueError('data size must be 28')
        pack = cls.STRUCT_TINY.unpack(data)

        if msg_type and pack[cls.MSGTYPE_ID - 2] != msg_type:
            raise ValueError('invalid message type')

        if pack[cls.VERSION_ID - 2] != cls.VERSION:
            raise ValueError('invalid protocol version')

        return FrameHeader(0, 0, pack[1], *pack[3:])

    @classmethod
    def unpack_receipt_from_raw(cls, data):
        """
        Unpack container header directly from bytearray without `length` and `CRC` fields.

        :param data: container header.
        :return: structured ContainerHeader.
        """
        if len(data) != cls.STRUCT_TINY.size:
            raise ValueError('data size must be 28')
        pack = cls.STRUCT_TINY.unpack(data)

        if pack[cls.MSGTYPE_ID - 2] != cls.MSGTYPE:
             raise ValueError('invalid message type')
        if pack[cls.VERSION_ID - 2] != cls.VERSION:
            raise ValueError('invalid protocol version')

        return FrameHeader(0, 0, pack[1], *pack[3:])

    def docnum(self):
        return struct.unpack('>I', b'\0' + self._docnum)[0]

    def recalculate_crc(self, body):
        f = crcmod.predefined.mkPredefinedCrcFun('crc-ccitt-false')
        pack = self.pack()
        self.crc = f(pack[:2] + pack[4:] + body)

    def __str__(self):
        return 'Заголовок Контейнера\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}'.format(
                                'Длина', self.length,
                                'Проверочный код', self.crc,
                                'Тип сообщения протокола', self.MSGTYPE,
                                'Тип фискального документа', self.doctype,
                                'Версия протокола', self.version,
                                'Служебные данные 1', self.extra1,
                                'Номер ФН', self.devnum,
                                'Номер ФД', self.docnum(),
                                'Служебные данные 2', self.extra2)


PAYMENT_DOCUMENTS = {'receipt', 'receiptCorrection', 'bso', 'bsoCorrection'}


class DocCodes:
    FISCAL_REPORT = 1
    FISCAL_REPORT_CORRECTION = 11
    OPEN_SHIFT = 2
    CURRENT_STATE_REPORT = 21
    RECEIPT = 3
    RECEIPT_CORRECTION = 31
    BSO = 4
    BSO_CORRECTION = 41
    CLOSE_SHIFT = 5
    CLOSE_ARCHIVE = 6
    OPERATOR_ACK = 7


# англоязычные name могут повторяться в тегах, русскоязычный description - уникальный для каждого тега
DOCUMENTS = {
    DocCodes.FISCAL_REPORT: STLV(u'fiscalReport', u'Отчёт о фискализации', maxlen=658),
    DocCodes.FISCAL_REPORT_CORRECTION: STLV(u'fiscalReportCorrection', u'Отчёт об изменении параметров регистрации',
                                            maxlen=658),
    DocCodes.OPEN_SHIFT: STLV(u'openShift', u'Отчёт об открытии смены', maxlen=440),
    DocCodes.CURRENT_STATE_REPORT: STLV(u'currentStateReport', u'Отчёт о текущем состоянии расчетов', maxlen=32768),
    DocCodes.RECEIPT: STLV(u'receipt', u'Кассовый чек', maxlen=32768),
    DocCodes.RECEIPT_CORRECTION: STLV(u'receiptCorrection', u'Кассовый чек коррекции', maxlen=32768),
    DocCodes.BSO: STLV(u'bso', u'Бланк строгой отчетности', maxlen=32768),
    DocCodes.BSO_CORRECTION: STLV(u'bsoCorrection', u'Бланк строгой отчетности коррекции', maxlen=32768),
    DocCodes.CLOSE_SHIFT: STLV(u'closeShift', u'Отчёт о закрытии смены', maxlen=441),
    DocCodes.CLOSE_ARCHIVE: STLV(u'closeArchive', u'Отчёт о закрытии фискального накопителя', maxlen=432),
    DocCodes.OPERATOR_ACK: STLV(u'operatorAck', u'подтверждение оператора', maxlen=512),

    1000: String(u'docName', u'наименование документа', maxlen=256),  # есть в протоколе, но не отправляется в ФНС
    1001: Byte(u'autoMode', u'автоматический режим'),
    1002: Byte(u'offlineMode', u'автономный режим'),
    1003: String(u'<unknown-1003>', u'адрес банковского агента', maxlen=256),
    1004: String(u'<unknown-1004>', u'адрес банковского субагента', maxlen=256),
    1005: [String(u'operatorTransferAddress', u'адрес оператора по переводу', maxlen=256, parents=[3, 4]),
           String(u'paymentProviderAddress', u'адрес оператора по переводу', maxlen=256, parents=[1223])],
    1006: String(u'<unknown-1006>', u'адрес платежного агента', maxlen=256),
    1007: String(u'<unknown-1007>', u'адрес платежного субагента', maxlen=256),
    1008: String(u'buyerPhoneOrAddress', u'адрес покупателя', maxlen=64),
    1009: String(u'retailAddress', u'адрес (место) расчетов', maxlen=256),
    1010: VLN(u'paymentAgentRemuneration', u'Размер вознаграждения банковского агента (субагента)'),
    1011: VLN(u'paymentAgentRemuneration-del', u'Размер вознаграждения платежного агента (субагента)'),
    1012: UnixTime(u'dateTime', u'дата, время'),
    1013: String(u'kktNumber', u'Заводской номер ККТ', maxlen=20),
    1014: String(u'<unknown-1014>', u'значение типа строка', maxlen=64),
    1015: U32(u'<unknown-1015>', u'значение типа целое'),
    1016: [String(u'operatorTransferInn', u'ИНН оператора по переводу денежных средств', maxlen=12, parents=[3, 4],
                  strip=True),
           String(u'paymentProviderInn', u'ИНН оператора перевода', maxlen=12, parents=[1223], strip=True)],
    1017: String(u'ofdInn', u'ИНН ОФД', maxlen=12, strip=True),
    1018: String(u'userInn', u'ИНН пользователя', maxlen=12, strip=True),
    1019: String(u'<unknown-1019>', u'Информационное cообщение', maxlen=64),
    1020: VLN(u'totalSum', u'ИТОГ', parents=[3, 31, 4, 41]),
    1021: String(u'operator', u'Кассир', maxlen=64),
    1022: Byte(u'ofdResponseCode', u'код ответа ОФД'),  # name выбрано самостоятельно
    1023: FVLN(u'quantity', u'Количество', maxlen=8),
    1024: String(u'<unknown-1024>', u'Наименование банковского агента', maxlen=64),
    1025: String(u'<unknown-1025>', u'Наименование банковского субагента', maxlen=64),
    1026: [String(u'operatorTransferName', u'Наименование оператора по переводу денежных средств', 64, parents=[3, 4]),
           String(u'paymentProviderName', u'Наименование оператора по переводу денежных средств', 64, parents=[1223])],
    1027: String(u'<unknown-1027>', u'Наименование платежного агента', maxlen=64),
    1028: String(u'<unknown-1028>', u'Наименование платежного субагента', maxlen=64),
    1029: String(u'<unknown-1029>', u'наименование реквизита', maxlen=64),
    1030: String(u'name', u'Наименование товара', maxlen=128),
    1031: VLN(u'cashTotalSum', u'Наличными'),
    1032: STLV(u'<unknown-1032>', u'Налог', maxlen=33),
    1033: STLV(u'<unknown-1033>', u'Налоги', maxlen=33),
    1034: FVLN(u'markup', u'Наценка (ставка)', maxlen=8),
    1035: VLN(u'markupSum', u'Наценка (сумма)'),
    1036: String(u'machineNumber', u'Номер автомата', maxlen=20),
    1037: String(u'kktRegId', u'Номер ККТ', maxlen=20),
    1038: U32(u'shiftNumber', u'Номер смены'),
    1039: String(u'<unknown-1039>', u'Зарезервирован', maxlen=12),
    1040: U32(u'fiscalDocumentNumber', u'номер фискального документа'),
    1041: String(u'fiscalDriveNumber', desc=u'заводской номер фискального накопителя', maxlen=16),
    1042: U32(u'requestNumber', u'номер чека за смену'),
    1043: VLN(u'sum', u'Общая стоимость позиции с учетом скидок и наценок'),
    1044: [String(u'paymentAgentOperation', u'Операция банковского агента', maxlen=24, parents=[3, 4]),
           String(u'agentOperation', u'Операция банковского агента', maxlen=24, parents=[1223])],
    1045: String(u'bankSubagentOperation', u'операция банковского субагента', maxlen=24),
    1046: String(u'ofdName', u'ОФД', maxlen=256),
    1047: STLV(u'<unknown-1047>', u'параметр настройки', maxlen=144),
    1048: String(u'user', u'наименование пользователя', maxlen=256),
    1049: String(u'<unknown-1049>', u'Почтовый индекс', maxlen=6),
    1050: Byte(u'fiscalDriveExhaustionSign', u'Признак исчерпания ресурса ФН'),
    1051: Byte(u'fiscalDriveReplaceRequiredSign', u'Признак необходимости срочной замены ФН'),
    1052: Byte(u'fiscalDriveMemoryExceededSign', u'Признак переполнения памяти ФН'),
    1053: Byte(u'ofdResponseTimeoutSign', u'Признак превышения времени ожидания ответа ОФД'),
    1054: Byte(u'operationType', u'Признак расчета'),
    1055: Byte(u'taxationType', u'применяемая система налогообложения', parents=[3, 31, 4, 41]),
    1056: Byte(u'encryptionSign', u'Признак шифрования'),
    1057: Byte(u'paymentAgentType', u'Применение платежными агентами (субагентами)'),
    1058: Byte(u'<unknown-1058>', u'Применение банковскими агентами (субагентами)'),
    1059: STLV(u'items', u'наименование товара (реквизиты)', 328, '*'),
    1060: String(u'fnsSite', u'Сайт налогового органа', maxlen=64),  # our name
    1061: String(u'ofdSite', u'Сайт ОФД', maxlen=64),  # our name
    1062: Byte(u'taxationType', u'системы налогообложения', parents=[1, 11]),
    1063: FVLN(u'discount', u'Скидка (ставка)', 8),
    1064: VLN(u'discountSum', u'Скидка (сумма)'),
    1065: String(u'<unknown-1065>', u'Сокращенное наименование налога', maxlen=10),
    1066: String(u'<unknown-1066>', u'Сообщение', maxlen=256),
    1067: STLV(u'<unknown-1067>', u'Сообщение оператора для ККТ', maxlen=216),
    1068: STLV(u'messageToFn', u'сообщение оператора для ФН', maxlen=169),  # name выбрано самостоятельно
    1069: STLV(u'<unknown-1069>', u'Сообщение оператору', 328, '*'),
    1070: FVLN(u'<unknown-1070>', u'Ставка налога', maxlen=5),
    1071: STLV(u'stornoItems', u'сторно товара (реквизиты)', 328, '*'),
    1072: VLN(u'<unknown-1072>', u'Сумма налога', maxlen=8),
    1073: String(u'paymentAgentPhone', u'Телефон банковского агента', maxlen=19, cardinality='*'),
    1074: [String(u'operatorToReceivePhone', u'Телефон платежного агента', maxlen=19, cardinality='*', parents=[3, 4]),
           String(u'paymentProviderPhone', u'Телефон платежного агента', maxlen=19, cardinality='*', parents=[1223])],
    1075: [String(u'operatorPhoneToTransfer', u'Телефон оператора по переводу денежных средств', 19, cardinality='*',
                  parents=[3, 4]),
           String(u'agentPhone', u'Телефон оператора перевода', 19, cardinality='*', parents=[1223])],
    1076: String(u'type', u'Тип сообщения', maxlen=64),
    1077: VLN(u'fiscalSign', u'фискальный признак документа', maxlen=6),
    1078: ByteArray(u'<unknown-1078>', u'фискальный признак оператора', maxlen=18),
    1079: VLN(u'price', u'Цена за единицу'),
    1080: String(u'barcode', u'Штриховой код EAN13', maxlen=16),
    1081: VLN(u'ecashTotalSum', u'форма расчета – электронными'),
    1082: String(u'bankSubagentPhone', u'телефон банковского субагента', maxlen=19),
    1083: String(u'paymentSubagentPhone', u'телефон платежного субагента', maxlen=19),
    1084: STLV(u'propertiesUser', u'дополнительный реквизит', 328),
    1085: String(u'propertyName', u'наименование дополнительного реквизита', maxlen=64),
    1086: String(u'propertyValue', u'значение дополнительного реквизита', maxlen=256),
    # 1087: u'Итог смены',
    # 1088:
    # 1089:
    # 1090:
    # 1091:
    # 1092:
    # 1093:
    # 1094:
    # 1095:
    # 1096:
    1097: U32(u'notTransmittedDocumentsQuantity', u'количество непереданных документов ФД'),
    1098: UnixTime(u'notTransmittedDocumentsDateTime', u'дата и время первого из непереданных ФД'),
    # 1099:
    # 1100:
    1101: Byte(u'correctionReasonCode', u'код причины перерегистрации', cardinality='+'),
    1102: VLN(u'nds18', u'НДС итога чека со ставкой 18%'),
    1103: VLN(u'nds10', u'НДС итога чека со ставкой 10%'),
    1104: VLN(u'nds0', u'НДС итога чека со ставкой 0%'),
    1105: VLN(u'ndsNo', u'НДС не облагается'),
    1106: VLN(u'ndsCalculated18', u'НДС итога чека с рассчитанной ставкой 18%'),
    1107: VLN(u'ndsCalculated10', u'НДС итога чека с рассчитанной ставкой 10%'),
    1108: Byte(u'internetSign', u'признак расчетов в сети Интернет'),
    1109: Byte(u'serviceSign', u'признак работы в сфере услуг'),
    1110: Byte(u'bsoSign', u'применяется для формирования БСО'),
    1111: U32(u'documentsQuantity', u'количество фискальных документов за смену'),
    1112: STLV(u'modifiers', u'скидка/наценка', 160, '*'),
    1113: String(u'discountName', u'наименование скидки', 64),
    1114: String(u'markupName', u'наименование наценки', 64),
    1115: String(u'addressToCheckFiscalSign', u'адрес сайта для проверки ФП', 256),
    1116: U32(u'notTransmittedDocumentNumber', u'номер первого непереданного документа'),
    1117: String(u'sellerAddress', u'адрес электронной почты отправителя чека', 64),
    1118: U32(u'receiptsQuantity', u'количество кассовых чеков за смену'),
    1119: String(u'operatorPhoneToReceive', u'телефон оператора по приему платежей', 19),
    # 1120:
    # 1121:
    # 1122:
    # 1123:
    # 1124:
    # 1125:
    1126: Byte(u'lotterySign', u'признак проведения лотереи'),
    1129: STLV(u'sellOper', u'счетчики операций "приход"', 116),
    1130: STLV(u'sellReturnOper', u'счетчики операций "возврат прихода"', 116),
    1131: STLV(u'buyOper', u'счетчики операций "расход"', 116),
    1132: STLV(u'buyReturnOper', u'счетчики операций "возврат расхода"', 116),
    1133: STLV(u'receiptCorrection', u'счетчики операций по чекам коррекции', 216),
    1134: U32(u'receiptCount', u'количество чеков со всеми признаками расчетов', parents=[1157, 1194, 1158]),
    1135: U32(u'receiptCount', u'количество чеков по признаку расчетов', parents=[1129, 1130, 1131, 1132]),
    1136: VLN(u'cashSum', u'сумма расчетов наличными'),
    1138: VLN(u'ecashSum', u'сумма расчетов электронными'),
    1139: VLN(u'tax18Sum', u'сумма НДС по ставке 18%'),
    1140: VLN(u'tax10Sum', u'сумма НДС по ставке 10%'),
    1141: VLN(u'tax18118Sum', u'сумма НДС по расч. ставке 18/118'),
    1142: VLN(u'tax10110Sum', u'сумма НДС по расч. ставке 10/110'),
    1143: VLN(u'tax0Sum', u'сумма расчетов с НДС по ставке 0%'),
    1144: U32(u'receiptCorrectionCount', u'количество чеков коррекции'),
    1145: STLV(u'sellCorrection', u'счетчики коррекций "приход"', 100),
    1146: STLV(u'buyCorrection', u'счетчики коррекций "расход"', 100),
    1147: U32(u'1147', u'количество операций коррекции'),
    1148: U32(u'selfCorrectionCount', u'количество самостоятельных корректировок'),
    1149: U32(u'orderCorrectionCount', u'количество корректировок по предписанию'),
    1150: VLN(u'correctionSum', u'сумма коррекций'),
    1151: VLN(u'tax18CorrectionSum', u'сумма коррекций НДС по ставке 18%'),
    1152: VLN(u'tax10CorrectionSum', u'сумма коррекций НДС по ставке 10%'),
    1153: VLN(u'tax18118CorrectionSum', u'сумма коррекций НДС по расч. ставке 18/118'),
    1154: VLN(u'tax10110CorrectionSum', u'сумма коррекций НДС расч. ставке 10/110'),
    1155: VLN(u'tax08CorrectionSum', u'сумма коррекций с НДС по ставке 0%'),
    1157: STLV(u'fiscalDriveSumReports', u'счетчики итогов ФН', 708),
    1158: STLV(u'notTransmittedDocumentsSumReports', u'счетчики итогов непереданных ФД', 708),
    1162: ByteArray(u'productCode', u'код товарной номенклатуры', 32),
    1171: String(u'providerPhone', u'телефон поставщика', 19),
    1173: Byte(u'correctionType', u'тип коррекции'),
    1174: STLV(u'correctionBase', u'основание для коррекции', 292),
    1177: String(u'correctionName', u'наименование основания для коррекции', 256),
    1178: UnixTime(u'correctionDocumentDate', u'дата документа основания для коррекции'),
    1179: String(u'correctionDocumentNumber', u'номер документа основания для коррекции', 32),
    1183: VLN(u'taxFreeSum', u'сумма расчетов без НДС'),
    1184: VLN(u'taxFreeCorrectionSum', u'сумма коррекций без НДС'),
    1187: String(u'retailPlace', u'место расчетов', 256),
    1188: String(u'kktVersion', u'версия ККТ', 8),
    1189: Byte(u'documentKktVersion', u'версия ФФД ККТ'),
    1190: Byte(u'documentFdVersion', u'версия ФФД ФН'),
    1191: [String(u'propertiesString', u'дополнительный реквизит предмета расчета', 256, parents=[3, 4]),
           String(u'propertiesItem', u'дополнительный реквизит предмета расчета', 256, parents=[1059, 1071])],
    1192: String(u'propertiesData', u'дополнительный реквизит чека (БСО)', 16),
    1193: Byte(u'gamblingSign', u'признак проведения азартных игр'),
    1194: STLV(u'shiftSumReports', u'счетчики итогов смены', 704),
    1195: String(u'sellerAddress-del', u'адрес электронной почты отправителя чека', 64),
    1196: String(u'1196', u'QR-код', 10000),
    1197: String(u'unit', u'единица измерения предмета расчета', 16),
    1198: VLN(u'unitNds', u'размер НДС за единицу предмета расчета'),
    1199: Byte(u'nds', u'ставка НДС'),
    1200: VLN(u'ndsSum', u'сумма НДС за предмет расчета'),
    1201: VLN(u'totalSum', u'общая сумма расчетов', parents=[1129, 1130, 1131, 1132]),
    1203: String(u'operatorInn', u'ИНН кассира', 12, parents=[1, 11, 2, 3, 4, 31, 41, 5, 6], strip=True),
    1205: U32(u'correctionKktReasonCode', u'коды причин изменения сведений о ККТ', cardinality='+'),
    1206: Byte(u'operatorMessage', u'сообщение оператора'),
    1207: Byte(u'exciseDutyProductSign', u'продажа подакцизного товара'),
    1208: String(u'1208', u'сайт чеков', 256),
    1209: Byte(u'fiscalDocumentFormatVer', u'версия ФФД'),
    1210: Byte(u'1210', u'признаки режимов работы ККТ'),
    1212: Byte(u'productType', u'признак предмета расчета'),
    1213: U32(u'fdKeyResource', u'ресурс ключей ФП'),
    1214: Byte(u'paymentType', u'признак способа расчета'),
    1215: VLN(u'prepaidSum', u'сумма предоплаты (зачет аванса)', parents=[3, 31, 41, 41]),
    1216: VLN(u'creditSum', u'сумма постоплаты (кредита)', parents=[3, 31, 4, 41]),
    1217: VLN(u'provisionSum', u'сумма встречным предоставлением', parents=[3, 31, 4, 41]),
    1218: VLN(u'prepaidSum', u'итоговая сумма в чеках (БСО) предоплатами', maxlen=6,
              parents=[1129, 1130, 1131, 1132, 1145, 1146]),
    1219: VLN(u'creditSum', u'итоговая сумма в чеках (БСО) постоплатами', maxlen=6,
              parents=[1129, 1130, 1131, 1132, 1145, 1146]),

    1220: VLN(u'provisionSum', u'итоговая сумма в чеках (БСО) встречными предоставлениями', maxlen=6),
    1221: Byte(u'printInMachineSign', u'признак установки принтера в автомате'),
    1222: Byte(u'paymentAgentByProductType', u'признак агента по предмету расчета'),
    1223: STLV(u'paymentAgentData', u'данные агента', maxlen=512),
    1224: STLV(u'providerData', u'данные поставщика', maxlen=512),
    1225: String(u'providerName', u'наименование поставщика', maxlen=256),
    1226: String(u'providerInn', u'ИНН поставщика', maxlen=12)
}

VERSIONS = {1: '1.0', 2: '1.05', 3: '1.1'}


def _group_tags(docs, group_by):
    """
    Группируем теги по указанному аттрибуту - т.к. поле неуникальное, то возможны коллизиции. В этом случае в значение
    пишем list всех соответствующих значений
    :param docs: исходный dict tag -> object
    :param group_by: наименование аттрибута, по которому происходит группировка
    :return: dict [group_by] -> object or list
    """
    result = {}
    for ty, doc in docs.items():
        if isinstance(doc, list):
            tags = doc
        else:
            tags = [doc]

        for t in tags:
            v = (ty, t)
            k = getattr(t, group_by)

            if k not in result:
                result[k] = v
            elif isinstance(v, list):
                result[k].append(v)
            else:
                result[k] = [result[k], v]

    return result


def _update_tag_value(doc):
    """
    В каждый объект внутри DOCUMENTS записать номера соответствующего ему тега
    Выполняется при инициализации
    """
    for ty, val in doc.items():
        if isinstance(val, list):
            for i in val:
                i.ty = ty
        else:
            val.ty = ty


DOCS_BY_DESC = _group_tags(DOCUMENTS, group_by='desc')
DOCS_BY_NAME = _group_tags(DOCUMENTS, group_by='name')
_update_tag_value(DOCUMENTS)  # инициализация тегов


class NullValidator(object):
    def validate(self, doc: dict, version: str):
        pass


class DocumentValidator(object):
    def __init__(self, versions, path, skip_unknown=False, min_date='2016.09.01', future_hours=24):
        """
        Класс для валидации документов от ККТ по json-схеме.
        :param versions: поддерживаемые версии протокола, например ['1.0', '1.05'].
        :param path: путь до директории, которая содержит все директории со схемами, разбитым по версиям,
        например, схемы для протокола 1.0 должны лежать в <path>/1.0/
        :param skip_unknown: если номер версии отличается от поддерживаемых пропускать валидацию
        """
        self._validators = {}
        self._skip_unknown = skip_unknown
        schema_dir = os.path.expanduser(path)
        schema_dir = os.path.abspath(schema_dir)

        self.min_date = datetime.datetime.strptime(min_date, '%Y.%m.%d') if min_date else None
        self.future_hours = future_hours

        for version in versions:
            full_path = os.path.join(schema_dir, version, 'document.schema.json')
            with open(full_path, encoding='utf-8') as fh:
                schema = json.loads(fh.read())
                resolver = jsonschema.RefResolver('file://' + full_path, None)
                validator = Draft4Validator(schema=schema, resolver=resolver)
                validator.check_schema(schema)  # проверяем, что сама схема - валидная
                self._validators[version] = validator

    def validate(self, doc: dict, version: str):
        """
        Валидация документа на соответствие json схеме протокола
        :param doc:
        :param version: номер версии, например '1.0' или '1.05'
        :return: Exception в случае ошибки валидации
        """
        validator = self._validators.get(version)
        if validator:
            validator.validate(doc)
        elif not self._skip_unknown:
            raise ValidationError('Version ' + version + ' is unsupported')

        self._validate_logic(doc)

    def _validate_logic(self, doc):
        doc_name = next(iter(doc))
        # проверка, что дата чека не меньше указанной даты
        doc_timestamp = doc[doc_name].get('dateTime')
        if self.min_date and self.min_date.timestamp() > doc_timestamp:
            doc_date = datetime.datetime.fromtimestamp(doc_timestamp)
            raise ValidationError('Document timestamp ' + str(doc_date) + ' is less than min. allowed date ' +
                                  str(self.min_date))

        # проверка, что чек может быть "из будущего" только на 24 часа больше UTC
        future = datetime.datetime.utcnow() + datetime.timedelta(hours=self.future_hours)
        if doc_timestamp > future.timestamp():
            doc_date = datetime.datetime.fromtimestamp(doc_timestamp)

            raise ValidationError('Document timestamp {} is greater than now for {} hours'
                                  .format(str(doc_date), str(self.future_hours)))


def _select_tag_by_key(key, docs, parent_ty):
    """
    workaround для решения проблемы протокола
    # один name может использоваться несколькими тегами (по протоколу ФНС)
    # в этом случае выбираем нужный тег на основе родительского - проверяем есть ли он в списке
    """
    val = docs[key]
    if isinstance(val, tuple):
        return val

    if not isinstance(val, list):
        raise ProtocolError('Value by key {} must be list or tuple: {}'.format(key, val))

    for el in val:
        parents = el[1].parents
        if parents and parent_ty in parents:
            return el
        elif parent_ty is None and not parents:
            return el

    # если соответствие не найдено, то кидаем ошибку - это лучшем, чем неправильно зашифровать ответ
    raise ProtocolError('Cant find correct tags for {} with parent {}'.format(key, parent_ty))


def pack_json(doc: dict, docs: dict = DOCS_BY_DESC, parent_ty=None) -> bytes:
    """
    Packs the given JSON document into a bytearray using optionally specified documents container.

    :param doc: valid JSON document as object.
    :param docs: documents container.
    :param parent_ty: value of parent tag. None for root element
    :return: packed document representation as a bytearray.
    """
    wr = b''
    for name, value in doc.items():
        ty, cls = _select_tag_by_key(key=name, docs=docs, parent_ty=parent_ty)
        if isinstance(value, list):
            # в случае массива записываем все элементы массива одним за другим
            # без родительского тега
            list_tags = b''
            for item in value:
                if isinstance(item, dict):
                    item_data = pack_json(item, docs=docs, parent_ty=ty)
                else:
                    item_data = cls.pack(item)
                list_tags += struct.pack('<HH', ty, len(item_data)) + item_data

            wr += list_tags
        else:
            if isinstance(value, dict):
                data = pack_json(value, docs=docs, parent_ty=ty)
            else:
                data = cls.pack(value)
            wr += struct.pack('<HH', ty, len(data)) + data

    return wr


MAX_UINT_32 = 2 ** 32 - 1  # максимальное значение 4-байтового uint


def extract_fiscal_sign_for_print(full_sign):
    """
    Хак. ФПД занимает 6 байт, но на чеке печатаются байты с 2 по 5. Если значение full_sign больше 4-байт unit, то
    выполяем преобразование, иначе возвращаем значение как есть
    """
    if full_sign <= MAX_UINT_32:
        return full_sign

    bn = struct.pack('>Q', full_sign)
    data = bn[2:6]
    return struct.unpack('<Q', data + b'\x00' * (8 - len(data)))[0]


class ProtocolPacker:
    @classmethod
    def unpack_container_message(cls, container_message_raw, fiscal_sign):
        ty, length = struct.unpack('<HH', container_message_raw[:4])
        stlv_doc = DOCUMENTS[ty]

        fps = VLN('fiscalSignOperator', 'фпс для оператора')

        container_message = stlv_doc.unpack(container_message_raw[4:4 + length])
        container_message['rawData'] = base64.b64encode(container_message_raw + fiscal_sign).decode('utf8')
        container_message['code'] = ty
        container_message['messageFiscalSign'] = fps.unpack(fiscal_sign)

        # тег 1000 (docName) не включается в док для ФНС
        if 'docName' in container_message:
            del container_message['docName']

        container_message = cls.format_message_fields(container_message)
        container_message = {stlv_doc.name: container_message}

        if not isinstance(container_message, dict):
            raise InvalidProtocolDocument()

        return container_message, stlv_doc

    @classmethod
    def format_message_fields(cls, container_message):
        if 'fiscalSign' in container_message:
            container_message['fiscalSign'] = extract_fiscal_sign_for_print(container_message['fiscalSign'])

        kkt_reg_id = container_message.get('kktRegId')
        if kkt_reg_id:
            container_message['kktRegId'] = kkt_reg_id.strip()

        inn_fields = ['userInn', 'ofdInn', 'operatorInn', 'operatorTransportInn']
        for field in inn_fields:
            if field in container_message:
                container_message[field] = cls._format_inn(container_message[field])

        phone_fields = ['paymentAgentPhone', 'operatorToReceivePhone', 'operatorPhoneToTransfer',
                        'bankSubagentPhone', 'paymentSubagentPhone']

        for field in phone_fields:
            if field in container_message:
                if isinstance(container_message[field], list):
                    container_message[field] = [cls._format_phone(i) for i in container_message[field]]
                else:
                    container_message[field] = cls._format_phone(container_message[field])

        return container_message

    @classmethod
    def _format_inn(cls, inn):
        if not inn:
            return inn

        inn = inn.strip()
        # некоторые кассы слева пишут нуля для 10-значных ИНН дополняя их до 12 символов
        # это нарушение формата, такие нули должны обрезаться
        if len(inn) > 10 and inn.startswith('00') and inn != '000000000000':
            inn = inn[2:]

        return inn

    @classmethod
    def _format_phone(cls, phone):
        if not phone:
            return phone

        phone = re.sub('[^0-9]', '', phone)
        if not phone:
            return phone

        return '+' + phone


def unpack_container_message(container_message_raw, fiscal_sign):
    return ProtocolPacker.unpack_container_message(container_message_raw, fiscal_sign)


def unpack_container_from_base64(container_message_b64, fiscal_sign):
    raw = base64.b64decode(container_message_b64)
    return unpack_container_message(raw, fiscal_sign)


def get_doc_name(doc):
    """
    Get actual document name from dict like {'receipt': {//actual body//}}
    :param doc: dict like {'doc_name': {//actual body//}}
    """
    if doc is None:
        return None
    return next(iter(doc))


def get_doc_body(doc):
    """
    Get actual document body from dict like {'receipt': {//actual body//}}
    It skips doc_name key and return body object with doc fields
    :param doc: dict like {'doc_name': {//actual body//}}
    :return: body object with doc fields
    """
    doc_name = get_doc_name(doc)
    if doc_name is None:
        return None
    return doc[doc_name]


def get_body_field(doc, field, default=None):
    """
    Get field from document body which is like {'receipt': {//actual body//}}
    It skips doc_name key and return field body object with doc fields
    :param doc: dict like {'doc_name': {//actual body//}}
    :param default: default value if field does not exists
    :param field: name of the body field
    :return: field from doc['doc_name'] dict or default value
    """
    body = get_doc_body(doc)
    return body.get(field, default)
