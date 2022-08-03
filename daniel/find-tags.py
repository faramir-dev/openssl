#!/usr/bin/env python3

# -*- coding: utf-8 -*-


import sys
import argparse
import base64
import traceback
import pprint


class DERParserException(BaseException):
    pass

class DERParserEOF(DERParserException):
    pass

TAG_IMPLICIT =          0x00
TAG_BOOLEAN =           0x01
TAG_INTEGER =           0x02
TAG_BIT_STRING =        0x03
TAG_OCTET_STRING =      0x04
TAG_NULL =              0x05
TAG_OBJECT_ID =         0x06
TAG_UTF8_STRING =       0x0c
TAG_SEQUENCE =          0x10
TAG_SET =               0x11
TAG_PRINTABLE_STRING =  0x13
TAG_T61_STRING =        0X14
TAG_IA5_STRING =        0X16
TAG_UTCTIME =           0X17
TAG_HIGH =              0x1f

tag_name = {
    TAG_IMPLICIT:           u"IMPLICIT",
    TAG_BOOLEAN:            u"BOOLEAN",
    TAG_INTEGER:            u"INTEGER",
    TAG_BIT_STRING:         u"BIT_STRING",
    TAG_OCTET_STRING:       u"OCTET_STRING",
    TAG_NULL:               u"NULL",
    TAG_OBJECT_ID:          u"OBJECT_ID",
    TAG_UTF8_STRING:        u"UTF8_STRING",
    TAG_SEQUENCE:           u"SEQUENCE",
    TAG_SET:                u"SET",
    TAG_PRINTABLE_STRING:   u"PRINTABLE_STRING",
    TAG_T61_STRING:         u"T61_STRING",
    TAG_IA5_STRING:         u"IA5_STRING",
    TAG_UTCTIME:            u"UTCTIME",
    TAG_HIGH:               u"<high tag>",
}

VARIABLE_LENGTH = -1

ENCODING_PRIMITIVE = 0
ENCODING_CONSTRUCTED = 1

class DERParser(object):
    """Parse DER file"""

    def __init__(self, stream):
        super(DERParser, self).__init__()
        self.stream = stream
        self.index = 0
        self.indent = 0

    def next_byte(self):
        try:
            byte = self.stream[self.index]
            self.index += 1
            return byte
        except IndexError:
            raise DERParserEOF

    def peek_byte(self):
        try:
            return self.stream[self.index]
        except IndexError:
            raise DERParserEOF

    def get_slice(self, length):
        try:
            slc = [x for x in self.stream[self.index:self.index + length]]
            self.index += length
            return slc
        except IndexError:
            raise DERParserEOF

    def parse_boolean(self, length):
        if length != 1:
            raise DERParserException(u"BOOLEAN length should be 1")
        return (length, self.next_byte() != 0)

    def parse_base128(self):
        value = 0
        size = 0
        while True:
            byte = self.next_byte()
            size += 1
            value = (value << 7) | (byte & 0x7f)
            if byte < 0x80:
                return (size, value)

    def parse_integer(self, length):
        value = 0
        value = self.next_byte()
        if value >= 0x80:
            value -= 256
        try:
            for i in range(length - 1):
                value = (value << 8) | self.next_byte()
        except DERParserEOF as e:
            print(f"Cannot parse integer of length: {length} -- Unexpected EOF :-(")
        
        return (length, value)

    def parse_bit_string(self, length):
        pad_bits = self.next_byte()
        octets = self.get_slice(length - 1)
        value = u"".join(u"{0:08b}".format(x) for x in octets)
        if pad_bits:
            value = value[:-pad_bits]
        return (length, value)

    def parse_octet_string(self, length):
        return (length, "".join(chr(x) for x in self.get_slice(length)))

    def parse_object_id(self, length):
        byte = self.next_byte()
        size = 1
        objid = u"%d.%d" % (int(byte / 40), byte % 40)
        while size < length:
            s, number = self.parse_base128()
            size += s
            objid += u".%d" % number
        return (length, objid)

    def parse_utf8_string(self, length):
        return (length, "".join(chr(x) for x in self.get_slice(length)).decode(u"utf-8"))

    def parse_end_of_seq(self):
        for i in range(2):
            byte = self.next_byte()
            if byte != 0:
                raise DERParserException(u"Unexpected byte 0x%02x in end of seq" % byte)

    def parse_sequence(self, length):
        sequence = list()
        size = 0
        self.indent += 4
        if length == VARIABLE_LENGTH:
            while True:
                if self.peek_byte() == 0:
                    self.parse_end_of_seq()
                    self.indent -= 4
                    break
                else:
                    s, obj = self.parse()
                    size += s
                    sequence.append(obj)
        else:
            while size < length:
                try:
                    s, obj = self.parse()
                    size += s
                    sequence.append(obj)
                except DERParserEOF:
                    print(f"Cannot parse sequence -- Unexpected EOF")
                    break
            self.indent -= 4
        return (size, tuple(sequence))

    def parse_ia5_string(self, length):
        return (length, "".join(chr(x) for x in self.get_slice(length)).decode(u"ascii"))


    def parse_length(self):
        byte = self.next_byte()
        if byte == 0x80:
            return VARIABLE_LENGTH
        elif byte < 0x80:
            return byte
        else:
            size = byte & 0x7f
            length = 0
            for i in range(size):
                length = (length << 8) | self.next_byte()
            return length


    def parse(self):
        self.integers = list()
        while True:
            offset = self.index

            byte = self.next_byte()
            type_class = byte >> 6
            encoding = (byte >> 5) & 1
            tag = byte & 0x1f

            if tag == TAG_HIGH:
                raise NotImplementedError(u"TAG_HIGH")

            try:
                length = self.parse_length()
                if length == VARIABLE_LENGTH:
                  length_str = u"variable length"
                elif length > 16*len(self.stream):
                  raise DERParserException(f"Invalid length {length}")
                else:
                  length_str = u"%d bytes" % length
            except DERParserEOF:
                length = None
                length_str = "Length Unknown - Unexpected EOF :-("

            print8(u"%s%04x: %02x = %d, %s %s, %s" % (
                u" " * self.indent,
                offset,
                byte,
                type_class,
                u"CONSTRUCTED" if encoding == ENCODING_CONSTRUCTED else u"PRIMITIVE",
                tag_name.get(tag, u"<unknown tag>"),
                length_str)
            )

            if length is None:
                raise DERParserEOF

            if tag == TAG_INTEGER:
                #repr_value = repr(value).decode(u"ascii")
                size, value = self.parse_integer(length)
                repr_value = repr(value)
                if len(repr_value) > 255:
                    repr_value = repr_value[:40] + u"..."
                print8(u"%s    value: %s" % (
                    u" " * self.indent,
                    repr_value
                ))
                self.integers.append(value)
            else:
                raise DERParserException("Unexpected tag")

            return self.integers


def print8(*args):
    print(u" ".join(args))


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument(u"-v", u"--verbose", action=u"store_true",
                   help=u"Verbose output.")
    p.add_argument(u"der")
    args = p.parse_args(argv[1:])

    with open(args.der) as f:
        content = f.read()

    result = list()
    integers = None
    while len(content) > 0:
        der = None
        der_content = content
        while len(der_content) > 0 and der is None:
            try:
                der = base64.b64decode(der_content)
            except:
                der_content = der_content[:-1]
        if der is None:
            break

        parser = DERParser(der)
    
        try:
            integers = parser.parse()
        except DERParserEOF:
            traceback.print_exc()
            integers = parser.integers
        except DERParserException:
            traceback.print_exc()
        except NotImplementedError:
            traceback.print_exc()

        if integers is not None and len(integers) > len(result):
            result = integers.copy()
        content = content[1:]
        pprint.pprint(integers)

    pprint.pprint(result)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
