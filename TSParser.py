#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'JiaSong'

TS_PKT_LEN = 188
TS_SYNC_BYTE = 0x47
PES_START_CODE = 0x010000  # PES分组起始标志0x000001
CRC32_LEN = 4
INVALID_VAL = -1

MAX_READ_PKT_NUM = 100
MAX_CHECK_PKT_NUM = 10

# PID type
PID_PAT, PID_NULL, PID_UNSPEC = 0x0000, 0x1fff, 0xffff
# Stream id
PES_STREAM_VIDEO, PES_STREAM_AUDIO = 0xE0, 0xC0
# Video stream type
ES_TYPE_MPEG1V, ES_TYPE_MPEG2V, ES_TYPE_MPEG4V, ES_TYPE_H264 = 0x01, 0x02, 0x10, 0x1b
# Audio stream type
ES_TYPE_MPEG1A, ES_TYPE_MPEG2A, ES_TYPE_AAC, ES_TYPE_AC3, ES_TYPE_DTS = 0x03, 0x04, 0x0f, 0x81, 0x8a

import sys
import ctypes
import os
from datetime import timedelta
from optparse import OptionParser

sizeof = ctypes.sizeof


def exit(code=0):
    if os.name == 'nt':
        os.system('pause')

    sys.exit(code)


def mk_word(high_bits, low_bits):
    return (high_bits << 8) | low_bits


def mk_pcr(bits1, bits2, bits3, bits4, bits5):
    return bits1 << 25 | bits2 << 17 | bits3 << 9 | bits4 << 1 | bits5


def mk_pts_dts(bits1, bits2, bits3, bits4, bits5):
    return bits1 << 30 | bits2 << 22 | bits3 << 15 | bits4 << 7 | bits5


def ts2second(timestamp):
    return timestamp/90000.0


class TSHdrFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('sync_byte', ctypes.c_uint8, 8),
        ('pid12_8', ctypes.c_uint8, 5),
        ('transport_priority', ctypes.c_uint8, 1),
        ('payload_unit_start_indicator', ctypes.c_uint8, 1),
        ('transport_error_indicator', ctypes.c_uint8, 1),
        ('pid7_0', ctypes.c_uint8, 8),
        ('continuity_counter', ctypes.c_uint8, 4),
        ('adaptation_field_control', ctypes.c_uint8, 2),
        ('transport_scrambling_control', ctypes.c_uint8, 2),
    ]


class AdaptFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('adaptation_field_length', ctypes.c_uint8, 8),
        ('adaptation_field_extension_flag', ctypes.c_uint8, 1),
        ('transport_private_data_flag', ctypes.c_uint8, 1),
        ('splicing_point_flag', ctypes.c_uint8, 1),
        ('OPCR_flag', ctypes.c_uint8, 1),
        ('PCR_flag', ctypes.c_uint8, 1),
        ('elementary_stream_priority_indicator', ctypes.c_uint8, 1),
        ('random_access_indicator', ctypes.c_uint8, 1),
        ('discontinuity_indicator', ctypes.c_uint8, 1),
    ]


class PCR(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('base32_25', ctypes.c_uint8, 8),
        ('base24_17', ctypes.c_uint8, 8),
        ('base16_9', ctypes.c_uint8, 8),
        ('base8_1', ctypes.c_uint8, 8),
        ('extension8', ctypes.c_uint8, 1),
        ('reserved', ctypes.c_uint8, 6),
        ('base0', ctypes.c_uint8, 1),
        ('extension7_0', ctypes.c_uint8, 8),
    ]


class PESHdrFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('packet_start_code_prefix', ctypes.c_uint32, 24),
        ('stream_id', ctypes.c_uint32, 8),
        ('PES_packet_length', ctypes.c_uint16, 16),
    ]


class OptionPESHdrFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('original_or_copy', ctypes.c_uint8, 1),
        ('copyright', ctypes.c_uint8, 1),
        ('data_alignment_indicator', ctypes.c_uint8, 1),
        ('PES_priority', ctypes.c_uint8, 1),
        ('PES_scrambling_control', ctypes.c_uint8, 2),
        ('fix_10', ctypes.c_uint8, 2),
        ('PES_extension_flag', ctypes.c_uint8, 1),
        ('PES_CRC_flag', ctypes.c_uint8, 1),
        ('additional_copy_info_flag', ctypes.c_uint8, 1),
        ('DSM_trick_mode_flag', ctypes.c_uint8, 1),
        ('ES_rate_flag', ctypes.c_uint8, 1),
        ('ESCR_flag', ctypes.c_uint8, 1),
        ('PTS_DTS_flags', ctypes.c_uint8, 2),
        ('PES_Hdr_data_length', ctypes.c_uint8, 8),
    ]


class PTS_DTS(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('marker_bit1', ctypes.c_uint8, 1),
        ('ts32_30', ctypes.c_uint8, 3),
        ('fix_4bits', ctypes.c_uint8, 4),  # PTS is '0010' or '0011', DTS is '0001'
        ('ts29_22', ctypes.c_uint8, 8),
        ('marker_bit2', ctypes.c_uint8, 1),
        ('ts21_15', ctypes.c_uint8, 7),
        ('ts14_7', ctypes.c_uint8, 8),
        ('marker_bit3', ctypes.c_uint8, 1),
        ('ts6_0', ctypes.c_uint8, 7),
    ]


class PATHdrFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('table_id', ctypes.c_uint8, 8),
        ('section_length11_8', ctypes.c_uint8, 4),
        ('reserved1', ctypes.c_uint8, 2),
        ('zero_bit', ctypes.c_uint8, 1),  # '0'
        ('section_syntax_indicator', ctypes.c_uint8, 1),
        ('section_length7_0', ctypes.c_uint8, 8),
        ('transport_stream_id', ctypes.c_uint16, 16),
        ('current_next_indicator', ctypes.c_uint8, 1),
        ('version_number', ctypes.c_uint8, 5),
        ('reserved2', ctypes.c_uint8, 2),
        ('section_number', ctypes.c_uint8, 8),
        ('last_section_number', ctypes.c_uint8, 8),
    ]


class PATSubSection(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('program_number', ctypes.c_uint16, 16),
        ('pid12_8', ctypes.c_uint8, 5),
        ('reserved', ctypes.c_uint8, 3),
        ('pid7_0', ctypes.c_uint8, 8),
    ]


class PMTHdrFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('table_id', ctypes.c_uint8, 8),
        ('section_length11_8', ctypes.c_uint8, 4),
        ('reserved1', ctypes.c_uint8, 2),
        ('zero_bit:1', ctypes.c_uint8, 1),  # '0'
        ('section_syntax_indicator', ctypes.c_uint8, 1),
        ('section_length7_0', ctypes.c_uint8, 8),
        ('transport_stream_id', ctypes.c_uint16, 16),
        ('current_next_indicator', ctypes.c_uint8, 1),
        ('version_number', ctypes.c_uint8, 5),
        ('reserved2', ctypes.c_uint8, 2),
        ('section_number', ctypes.c_uint8, 8),
        ('last_section_number', ctypes.c_uint8, 8),
        ('PCR_PID12_8', ctypes.c_uint8, 5),
        ('reserved3', ctypes.c_uint8, 3),
        ('PCR_PID7_0', ctypes.c_uint8, 8),
        ('program_info_length11_8', ctypes.c_uint8, 4),
        ('reserved4', ctypes.c_uint8, 4),
        ('program_info_length7_0', ctypes.c_uint8, 8),
    ]


class PMTSubSectionFixedPart(ctypes.LittleEndianStructure):
    _pack_ = 1  # 1字节对齐
    _fields_ = [
        ('stream_type', ctypes.c_uint8, 8),
        ('elementaryPID12_8', ctypes.c_uint8, 5),
        ('reserved1', ctypes.c_uint8, 3),
        ('elementaryPID7_0', ctypes.c_uint8, 8),
        ('ES_info_lengh11_8', ctypes.c_uint8, 4),
        ('reserved2', ctypes.c_uint8, 4),
        ('ES_info_lengh7_0', ctypes.c_uint8, 8),
    ]


class TSPacket:
    pid_map = {
        'PMT': PID_UNSPEC,
        'PCR': PID_UNSPEC,
        'VIDEO': PID_UNSPEC,
        'AUDIO': PID_UNSPEC,
    }

    def __init__(self, buf):
        self.buf = buf
        self.ts_header = None
        self.pid = PID_UNSPEC
        self.cc = INVALID_VAL
        self.pmt_pid = PID_UNSPEC
        self.stream_id = INVALID_VAL
        self.pcr = INVALID_VAL
        self.pts = INVALID_VAL
        self.dts = INVALID_VAL

    def parse(self):
        if not self.buf or (TS_PKT_LEN != len(self.buf)):
            print '###### Input data length is not 188 bytes!',len(self.buf),self.buf
            return False

        if TS_SYNC_BYTE != ord(self.buf[0]):
            print '###### The first byte of packet is not 0x47!'
            return False

        self.ts_header = TSHdrFixedPart.from_buffer_copy(self.buf[0:sizeof(TSHdrFixedPart)])
        self.pid = mk_word(self.ts_header.pid12_8, self.ts_header.pid7_0)
        self.cc = self.ts_header.continuity_counter

        if self.is_pat():
            self.__parse_pat()
        elif self.is_pmt():
            self.__parse_pmt()
        elif self.pid == TSPacket.pid_map['PCR']:
            self.pcr = self.__get_pcr()

        if self.__has_payload():
            self.__parse_pes()

        return True

    def is_pat(self):
        return PID_PAT == self.pid

    def is_pmt(self):
        return (PID_UNSPEC != self.pid) and (TSPacket.pid_map['PMT'] == self.pid)

    def is_video(self):
        return TSPacket.pid_map['VIDEO'] == self.pid

    def is_audio(self):
        return TSPacket.pid_map['AUDIO'] == self.pid

    def __has_adapt_field(self):
        return 0 != (self.ts_header.adaptation_field_control & 0x2)

    def __has_payload(self):
        return (self.ts_header.payload_unit_start_indicator == 1) or (self.ts_header.adaptation_field_control & 0x1)

    def __get_adapt_field(self):
        adapt = None
        if self.__has_adapt_field():
            adapt = AdaptFixedPart.from_buffer_copy(self.buf[sizeof(TSHdrFixedPart):])
        return adapt

    def __get_adapt_len(self):
        adapt_len = 0
        adapt = self.__get_adapt_field()
        if adapt:
            # 'adaptation_field_length' field is 1 byte
            adapt_len = adapt.adaptation_field_length + 1
        return adapt_len

    def __get_pcr(self):
        pcr_val = INVALID_VAL
        adapt = self.__get_adapt_field()
        if adapt and adapt.adaptation_field_length > 0 and adapt.PCR_flag:
            pcr = PCR.from_buffer_copy(self.buf[sizeof(TSHdrFixedPart) + sizeof(AdaptFixedPart):])
            pcr_val = mk_pcr(pcr.base32_25, pcr.base24_17, pcr.base16_9, pcr.base8_1, pcr.base0)
        return pcr_val

    def __is_video_stream(self, stream_type):
        return stream_type in (ES_TYPE_MPEG1V, ES_TYPE_MPEG2V, ES_TYPE_MPEG4V, ES_TYPE_H264)

    def __is_audio_stream(self, stream_type):
        return stream_type in (ES_TYPE_MPEG1A, ES_TYPE_MPEG2A, ES_TYPE_AC3, ES_TYPE_AAC, ES_TYPE_DTS)

    def __get_payload_offset(self):
        return sizeof(TSHdrFixedPart) + self.__get_adapt_len()

    def __get_table_start_pos(self):
        pos = 0
        if self.__has_payload():
            pos = self.__get_payload_offset()
            # 'pointer_field' field is 1 byte,
            # and whose value is the number of bytes before payload
            pos += ord(self.buf[pos]) + 1
        return pos

    def __get_pts(self, option_hdr_pos):
        pts_val = INVALID_VAL
        pts_pos = option_hdr_pos + sizeof(OptionPESHdrFixedPart)
        option_hdr = OptionPESHdrFixedPart.from_buffer_copy(self.buf[option_hdr_pos:pts_pos])
        if option_hdr.PTS_DTS_flags & 0x2:
            pts = PTS_DTS.from_buffer_copy(self.buf[pts_pos:pts_pos+sizeof(PTS_DTS)])
            pts_val = mk_pts_dts(pts.ts32_30, pts.ts29_22, pts.ts21_15, pts.ts14_7, pts.ts6_0)
        return pts_val

    def __get_dts(self, option_hdr_pos):
        dts_val = INVALID_VAL
        pts_pos = option_hdr_pos + sizeof(OptionPESHdrFixedPart)
        option_hdr = OptionPESHdrFixedPart.from_buffer_copy(self.buf[option_hdr_pos:pts_pos])
        if option_hdr.PTS_DTS_flags & 0x1:
            dts_pos = pts_pos + sizeof(PTS_DTS)
            dts = PTS_DTS.from_buffer_copy(self.buf[dts_pos:dts_pos+sizeof(PTS_DTS)])
            dts_val = mk_pts_dts(dts.ts32_30, dts.ts29_22, dts.ts21_15, dts.ts14_7, dts.ts6_0)
        return dts_val

    def __parse_pat(self):
        pat_pos = self.__get_table_start_pos()
        section_pos = pat_pos + sizeof(PATHdrFixedPart)
        pat = PATHdrFixedPart.from_buffer_copy(self.buf[pat_pos:section_pos])
        section_len = mk_word(pat.section_length11_8, pat.section_length7_0)
        all_subsection_len = section_len - sizeof(PATHdrFixedPart) - CRC32_LEN

        subsection_len = sizeof(PATSubSection)
        for i in xrange(0, all_subsection_len, subsection_len):
            tmp_buf = self.buf[section_pos+i:section_pos+i+subsection_len]
            descriptor = PATSubSection.from_buffer_copy(tmp_buf)
            pid = mk_word(descriptor.pid12_8, descriptor.pid7_0)
            if 0x00 == descriptor.program_number:
                network_pid = pid
            else:
                self.pmt_pid = pid  # program_map_PID
                break

        TSPacket.pid_map['PMT'] = self.pmt_pid

    def __parse_pmt(self):
        pmt_pos = self.__get_table_start_pos()
        section_pos = pmt_pos + sizeof(PMTHdrFixedPart)
        pmt = PMTHdrFixedPart.from_buffer_copy(self.buf[pmt_pos:section_pos])

        TSPacket.pid_map['PCR'] = mk_word(pmt.PCR_PID12_8, pmt.PCR_PID7_0)
        section_len = mk_word(pmt.section_length11_8, pmt.section_length7_0)
        # n * program_info_descriptor的长度
        program_info_len = mk_word(pmt.program_info_length11_8, pmt.program_info_length7_0)
        all_subsection_len = section_len - (sizeof(PMTHdrFixedPart) - 3) - program_info_len - CRC32_LEN

        subsection_len = sizeof(PMTSubSectionFixedPart)
        section_pos += program_info_len
        i = 0
        while i < all_subsection_len:
            tmp_buf = self.buf[section_pos+i:section_pos+i+subsection_len]
            sub_section = PMTSubSectionFixedPart.from_buffer_copy(tmp_buf)
            elementary_pid = mk_word(sub_section.elementaryPID12_8, sub_section.elementaryPID7_0)
            es_info_len = mk_word(sub_section.ES_info_lengh11_8, sub_section.ES_info_lengh7_0)
            i += subsection_len + es_info_len

            if self.__is_video_stream(sub_section.stream_type):
                TSPacket.pid_map['VIDEO'] = elementary_pid
            elif self.__is_audio_stream(sub_section.stream_type):
                TSPacket.pid_map['AUDIO'] = elementary_pid

    def __parse_pes(self):
        pes_pos = self.__get_payload_offset()
        option_hdr_pos = pes_pos + sizeof(PESHdrFixedPart)
        if option_hdr_pos > TS_PKT_LEN:
            return
        pes = PESHdrFixedPart.from_buffer_copy(self.buf[pes_pos:option_hdr_pos])
        if PES_START_CODE == pes.packet_start_code_prefix:
            self.stream_id = pes.stream_id
            if (pes.stream_id & PES_STREAM_VIDEO) or (pes.stream_id & PES_STREAM_AUDIO):
                self.pts = self.__get_pts(option_hdr_pos)
                self.dts = self.__get_dts(option_hdr_pos)


class TSParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.fd = None
        self.pkt_no = 0
        self.show_pid = PID_UNSPEC
        self.grep = 'ALL'

    def set_show_param(self, pid, grep):
        if pid is not None:
            self.show_pid = pid
        if grep:
            self.grep = grep

    def parse(self):
        self.__open_file()
        if not self.__seek_to_first_pkt():
            print '###### Seek to first packet failed!'
            exit(-1)

        cur_pos = self.fd.tell()
        print 'Seek to first packet, offset: 0x%08X' % cur_pos

        read_len = MAX_READ_PKT_NUM*TS_PKT_LEN
        try:
            while True:
                buf = self.fd.read(read_len)
                if not buf:
                    break
                real_len = len(buf)
                for i in xrange(0, real_len, TS_PKT_LEN):
                    pkt = TSPacket(buf[i:i+TS_PKT_LEN])
                    success = pkt.parse()
                    if not success:
                        print '###### Sync byte error! cur_pos<%d>, pkt_no<%d>' % (cur_pos, self.pkt_no+1)
                    if success and self.__is_show_pkt(pkt):
                        self.__print_packet_info(pkt, cur_pos)
                    cur_pos += TS_PKT_LEN
                    self.pkt_no += 1

            print 'Parse file complete!'
        except IOError as (errno, strerror):
            print '###### Read file error! error({0}): {1}'.format(errno, strerror)

        self.__close_file()

    def __open_file(self):
        try:
            self.fd = open(self.file_path, 'rb')
            print 'Open file<%s> success.' % self.file_path
        except IOError as (errno, strerror):
            print '###### Open file<%s> failed! error({0}): {1}'.format(errno, strerror)
            exit(-1)

    def __close_file(self):
        if self.fd:
            self.fd.close()
            self.fd = None
            print 'Close file<%s>' % self.file_path

    def __seek_to_first_pkt(self):
        try:
            buf = self.fd.read(MAX_READ_PKT_NUM * TS_PKT_LEN)
            loop_num = len(buf) - MAX_CHECK_PKT_NUM * TS_PKT_LEN
            for i in xrange(0, loop_num):
                if ord(buf[i]) == TS_SYNC_BYTE:
                    for n in xrange(0, MAX_CHECK_PKT_NUM):
                        if ord(buf[i + n * TS_PKT_LEN]) != TS_SYNC_BYTE:
                            break
                    else:
                        self.fd.seek(i)
                        return True
        except IOError as (errno, strerror):
            print '###### Read file error! error({0}): {1}'.format(errno, strerror)

        return False

    def __is_show_pkt(self, pkt):
        show = True
        if PID_UNSPEC != self.show_pid:
            show = pkt.pid == self.show_pid
        elif 'ALL' != self.grep:
            show = pkt.is_pat() and 'PAT' in self.grep
            show = show or pkt.is_pmt() and 'PMT' in self.grep
            show = show or pkt.pcr > 0 and 'PCR' in self.grep
            show = show or pkt.pts > 0 and 'PTS' in self.grep
            show = show or pkt.dts > 0 and 'DTS' in self.grep
        return show

    def __print_packet_info(self, pkt, offset):
        args = (self.pkt_no, offset, pkt.pid, pkt.cc)
        print 'PktNo: %08u, Offset: 0x%08X, PID: 0x%04X, CC: %02u' % args,

        if pkt.is_pat():
            print ', PAT',
        elif pkt.is_pmt():
            print ', PMT',
        elif pkt.pcr >= 0:
            print ', PCR: %d(%s)' % (pkt.pcr, timedelta(seconds=ts2second(pkt.pcr))),
        elif PID_NULL == pkt.pid:
            print ', Null Packet',

        if pkt.pts >= 0:
            print ', PTS: %d(%s)' % (pkt.pts, timedelta(seconds=ts2second(pkt.pts))),
        if pkt.dts >= 0:
            print ', DTS: %d(%s)' % (pkt.dts, timedelta(seconds=ts2second(pkt.dts))),

        if pkt.is_video():
            print ', Video',
        elif pkt.is_audio():
            print ', Audio',

        print ''


def main():
    usage = 'Usage: %prog filepath [Options]\n\n'
    usage += '  filepath              the mpeg-ts file'
    parser = OptionParser(usage=usage)
    parser.add_option('-p', '--pid', type='int', help='only show the specific pid')
    parser.add_option('-g', '--grep', help='show the specific package type, such as "PAT,PMT,PCR,PTS,DTS"')
    opts, args = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        exit(0)
    if opts.pid is not None and opts.grep:
        parser.error('options -p/--pid and -g/--grep are mutually exclusive')
        exit(0)

    try:
        ts_parser = TSParser(args[0])
        ts_parser.set_show_param(opts.pid, opts.grep)
        ts_parser.parse()
    except KeyboardInterrupt:
        print '\n^C received, Exit.'

if __name__ == '__main__':
    main()
    exit(0)

