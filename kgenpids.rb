#!/usr/bin/ruby

require 'zlib'  # use crc32 in zlib

module Genpid

    @@char_map3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    @@char_map4 = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

    # Returns two bit at offset from a bit field
    def get_two_bits_from_bit_field(bit_field, offset)
        byte_num = offset / 4
        bit_pos = 6 - 2*(offset % 4)

        return bit_field[byte_num].ord >> bit_pos & 3
    end

    # Returns the six bits at offset from a bit field
    def get_six_bits_from_bit_field(bit_field, offset)
        offset *= 3
        value = (get_two_bits_from_bit_field(bit_field,offset) <<4) + (get_two_bits_from_bit_field(bit_field,offset+1) << 2) +get_two_bits_from_bit_field(bit_field,offset+2)
    
        return value
    end

    def encode_pid(hash)
        pid = ''
        for position in 0...8
            pid += @@char_map3[get_six_bits_from_bit_field(hash, position)]
        end

        return pid    
    end

    def checksum_pid(s)
        crc = (~Zlib::crc32(s, -1)) & 0xFFFFFFFF
        crc = crc ^ (crc >> 16)
        res = s
        l = @@char_map4.length
        for i in 0..1
            b = crc & 0xff
            pos = (b / l) ^ (b % l)
            res += @@char_map4[pos%l]
            crc >>= 8
        end

        return res
    end

    # Parse the EXTH header records and use the Kindle serial number to calculate the book pid.
    def get_kindle_pid(pidlist, tamper_proof_key, token, serialnum)
        pidhash = Digest::SHA1.digest(serialnum + tamper_proof_key + token)
        bookpid = encode_pid(pidhash)
        bookpid = checksum_pid(bookpid)
        pidlist << bookpid
    end
end
