#!/usr/bin/ruby

require 'zlib'  # use crc32 in zlib

#global variable
$charMap3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
$charMap4 = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

# Returns two bit at offset from a bit field
def getTwoBitsFromBitField(bitField,offset)
    byteNumber = offset / 4
    bitPosition = 6 - 2*(offset % 4)

    return bitField[byteNumber].ord >> bitPosition & 3
end

# Returns the six bits at offset from a bit field
def getSixBitsFromBitField(bitField, offset)
    offset *= 3
    value = (getTwoBitsFromBitField(bitField,offset) <<4) + (getTwoBitsFromBitField(bitField,offset+1) << 2) +getTwoBitsFromBitField(bitField,offset+2)
    
    return value
end

def encodePID(hash)
    pid = ''
    for position in 0...8
        pid += $charMap3[getSixBitsFromBitField(hash, position)]
    end

    return pid    
end

def checksumPid(s)
    crc = (~Zlib.crc32(s, -1)) & 0xFFFFFFFF
    crc = crc ^ (crc >> 16)
    res = s
    l = $charMap4.length
    for i in 0..1
        b = crc & 0xff
        pos = (b / l) ^ (b % l)
        res += $charMap4[pos%l]
        crc >>= 8
    end

    return res
end

# Parse the EXTH header records and use the Kindle serial number to calculate the book pid.
def getKindlePid(pidlist, rec209, token, serialnum)
    pidHash = Digest::SHA1.digest(serialnum+rec209+token)
    bookPID = encodePID(pidHash)
    bookPID = checksumPid(bookPID)
    pidlist << bookPID

    return pidlist
end

