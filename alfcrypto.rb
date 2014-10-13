#!/usr/bin/ruby

def PC1(key, src, decryption=true)
    sum1 = 0
    sum2 = 0
    keyXorVal = 0
    if key.length !=16
        print "Bad key length!\n"
        return nil
    end    

    wkey = []
    for i in 0...8 do 
        wkey << (key[i*2].unpack('C')[0]<<8 | key[i*2+1].unpack('C')[0])
    end

    dst = ""
    for i in 0...src.length do
        temp1 = 0
        byteXorVal = 0
        for j in 0...8 do 
            temp1 ^= wkey[j]
            sum2  = (sum2+j)*20021 + sum1
            sum1  = (temp1*346)&0xFFFF
            sum2  = (sum2+sum1)&0xFFFF
            temp1 = (temp1*20021+1)&0xFFFF
            byteXorVal ^= temp1 ^ sum2
        end
        curByte = src[i].ord
        if decryption == false
            keyXorVal = curByte * 257
        end

        curByte = ((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF
        if decryption == true
            keyXorVal = curByte * 257
        end
        for j in 0...8
            wkey[j] ^= keyXorVal
        end
        dst += curByte.chr
    end

    return dst
end

