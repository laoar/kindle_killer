#!/usr/bin/ruby

# Script for remove drm from amazon ebook in CLI.
# writed by @yfshao
#
# Reference:
# 1. MOBI format: http://wiki.mobileread.com/wiki/MOBI
# 2. Alfcrypto: http://apprenticealf.wordpress.com/ (requires VPN)

require 'digest/sha1'    #for sha1 algorithm
require './kgenpids'; include Genpid
require './alfcrypto'; include Alf


def get_size_of_trailing_data_entries(ptr, size, flags)
    def get_size_of_trailing_data_entry(ptr, size)
        bitpos, result = 0, 0
        if size <= 0
            return result
        end

        while true do
            v = ptr[size-1].ord
            result |= (v & 0x7F) << bitpos
            bitpos += 7
            size -= 1
            if (v & 0x80) != 0 || (bitpos >= 28) || (size == 0)
                return result
            end
        end

    end

    num = 0 
    testflags = flags >> 1
    while testflags != 0 
        if testflags & 1
            num += get_size_of_trailing_data_entry(ptr, size - num)
        end
        testflags >>= 1
    end

    # Check the low bit to see if there's multibyte data present.
    # if multibyte data is included in the encryped data, we'll
    # have already cleared this flag.
    if flags & 1
        num += (ptr[size - num - 1].ord & 0x3) + 1 
    end

    return num 
end


class MobiBook
    def get_book_title
        updated_title = ''    
        if @magic == 'BOOKMOBI'
            if @exth_record.has_key?503
                updated_title = @exth_record[503]
            else
                toff, tlen = @sect[0x54...0x5c].unpack('I>I>')
                tend = toff + tlen
                updated_title = @sect[toff...tend]
            end    
        end

        if updated_title == ''
            updated_title = @header[0...32]
            updated_title = updated_title.split("\0"[0])
        end

        return updated_title
    end

    def get_pid_meta_info
        tamper_proof_key = ''
        token = ''
        if @exth_record.has_key?209
            # It is used by the Kindle for generating book-specific PIDs.
            tamper_proof_key = @exth_record[209]
            data = tamper_proof_key
            #The 209 data comes in five byte groups.
            #Interpret the last four bytes of each group 
            #as a big endian unsigned integer to get a key value
            #if that key exists in the exth_record,
            #append its contents to the token    
            for i in 0...data.length
                val, = data[i+1...i+5].unpack('I>')
                sval = @exth_record.fetch(val, '') 
                token += sval
                i = i + 5
            end
        end

        return tamper_proof_key, token
    end

    def process_book(pidlist)
        crypto_type, = @sect[0xC...0xC+2].unpack('S>')
        # Only type 0, 1, 2 are valid.
        @crypto_type = crypto_type
        if crypto_type == 0
            put "This book is not encrypted!"
            exit false 
        end

        if @crypto_type != 2 && @crypto_type != 1
            printf("unknown encryption type:%d\n", @crypto_type)
        end

        if @exth_record.include?406
            rent_expiration_date, = @exth_record[406].unpack('Q>') 
            if rent_expiration_date != 0
                puts "Cannot decode library or rented ebooks!"
                exit false 
            end
        end

        goodpids = []
        for pid in pidlist do
            if pid.length == 10
                if (checksum_pid(pid[0...-2]) != pid)
                    print "Warning: PID " + pid + " has incorrect checksum, should have been "+checksum_pid(pid[0...-2]) + "\n"
                end
                goodpids << pid[0...-2]
            elsif pid.length == 8
                goodpids << pid
            end
        end
        
        if @crypto_type == 1
            print "Old Mobipocket Encryptioin\n"
            t1_keyvec = "QDCVEPMU675RUBSZ"
            if @magic == 'TEXtREAd'
                bookkey_data = @sect[0x0E...0x0E+16]
            elsif @mobi_version < 0
                bookkey_data = @sect[0x90...0x90+16]
            else
                bookkey_data = @sect[@mobi_header_len+16...@mobi_header_len+32]
            end
            pid = "00000000"
            found_key = Alf::pc1(t1_keyvec, bookkey_data)
        elsif @crypto_type == 2 # 2
            puts "Mobipocket Encryption"
            # drm_offset : offset to DRM key info in DRMed file.
            #                0xffffffff if no DRM
            # drm_count : numbers of entries in DRM info. 
               #                0xffffffff if no DRM 
            # drm_size : Numbers of bytes in DRM info
            # drm_flags : Some flags concerning the DRM info     
            drm_offset, drm_count, drm_size, drm_flags = @sect[0xA8...0xA8+16].unpack('L>L>L>L>')
            found_key, pid = parse_drm(@sect[drm_offset...drm_offset+drm_size], drm_count, goodpids)

            # kill the drm keys
            patch_section(0, "\0" * drm_size, drm_offset)            
            # kill the drm pointers
            patch_section(0, "\xff" * 4 + "\0" * 12, 0xA8)
        end

        if pid=="00000000"
            puts "File has default encryption, no specific PID."
        else
            print "File is encoded with PID "+checksum_pid(pid)+ ".\n"
        end
        
        # clear the crypto type
        patch_section(0, "\0" * 2, 0xC)

        # decrypt sections
        print "Decrypting. Please wait . . ."

        mobidata_list = []
        mobidata_list << @data_file[0...@sections[1][0]]
        for i in 1...@records+1 do
            data = load_section(i)
            extra_size = 0
            extra_size = get_size_of_trailing_data_entries(data, data.length, @extra_data_flags)
            if i%10 == 0
                print "."
            end
            #printf("record %d, extra_size %d\n", i,extra_size)
            decoded_data = Alf::pc1(found_key, data[0...data.length - extra_size])
            mobidata_list << decoded_data
            if extra_size > 0
                mobidata_list << data[-extra_size...data.length]
            end
        end
        print "\n"

        if @num_sections > @records+1
            mobidata_list << @data_file[@sections[@records+1][0]...@data_file.length]
        end

        @mobi_data = ""
        mobidata_list.each { |x|
            @mobi_data << x
        }

        puts "Congrates! Mission done!"
    end

    def sect
        @sect
    end

    def mobi_data
        @mobi_data
    end

    private
    def load_section(index)
        if index + 1 == @num_sections
            endoff = @size
        else
            endoff = @sections[index+1][0]
        end
        off = @sections[index][0]

        return  @data_file[off...endoff] 
    end

    def initialize(file_name)
        file = File.open(file_name)
        @size = File.size(file_name)
        @data_file = file.sysread(@size)
        @magic = @data_file[60...68]
        @crypto_type = -1

        @num_sections, = @data_file[76...78].unpack("S>")

        @sections = []
        for index in 0...@num_sections do
            offset,a1,a2,a3,a4 = @data_file[78+index*8...78+index*8+8].unpack('L>CCCC')
            flags, val = a1, a2<<16|a3<<8|a4
            @sections.push([offset,flags,val])
        end

        @sect = load_section(0)

        # parse info from section[0]
        @records, = @sect[0x8...0x8+2].unpack('S>')
        @compression, = @sect[0x0...0x0+2].unpack('S>')
        @mobi_header_len, = @sect[0x14...0x18].unpack('L>')
        @mobi_codepage, = @sect[0x1c...0x20].unpack('L>')
        @mobi_version, = @sect[0x68...0x6C].unpack('L>')
        printf("MOBI header version = %d, length = %d\n", @mobi_version, @mobi_header_len)
        
        @extra_data_flags = 0
        if @mobi_header_len >= 0xE4 && @mobi_version >= 5
            @extra_data_flags, = @sect[0xF2...0xF4].unpack('S>')
            printf("Extra Data Flags = %d\n", @extra_data_flags)
        end

        if @compression != 17480
            @extra_data_flags &= 0xFFFE
        end

        # @exth_record is a Hash table.
        @exth_record = {} 
        exth_flag, = @sect[0x80...0x84].unpack('I>')
        exth = 'NONE'
        if exth_flag & 0x40 # bit6
            puts "There's an EXTH record!"
            # The EXTH header follows immediately after the MOBI header.
            exth = @sect[16 + @mobi_header_len...@sect.length] 
        end

        # exth[0...4] is the EXTH identifier
        if (exth.length >= 4) and (exth[0...4] == 'EXTH') 
            # The number of records in the EXTH header.
            nitems, = exth[8...12].unpack('I>')
            # EXTH record start 
            pos = 12
            for i in 0...nitems do
                type, size = exth[pos...pos + 8].unpack('I>I>')
                content = exth[pos + 8...pos + size]
                @exth_record[type] = content
                if type == 401 &&  size == 9 # clippinglimit : nteger percentage of the text allowed to be clipped. Usually 10.
                    patch_section(0, "\144", 16 + @mobi_header_len + pos + 8)
                elsif type == 404 && size == 9 # ttsflag
                    patch_section(0, "\0", 16 + @mobi_header_len + pos + 8)
                end
                pos += size
            end
        end

    end

    def patch(off, new)
        tmp = "".force_encoding("ASCII-8BIT")
        tmp << @data_file[0...off].force_encoding("ASCII-8BIT")
        tmp << new.force_encoding("ASCII-8BIT")
        tmp << @data_file[off + new.length...@data_file.length] 
        @data_file = tmp
    end

    def patch_section(section, new, in_off = 0)
        if section + 1 == @num_sections
            endoff = @data_file.length
        else
            endoff, = @sections[section + 1]
        end

        off, = @sections[section]
        patch(off + in_off, new)    
    end
    
    def parse_drm(data, count, pidlist)
        found_key = nil 
        keyvec1 = "\x72\x38\x33\xB0\xB4\xF2\xE3\xCA\xDF\x09\x01\xD6\xE2\xE0\x3F\x96"
#keyascii = [114, 56, 51, 176, 180, 242, 227, 202, 223, 9, 1, 214, 226, 224, 63, 150]
        for pid in pidlist do
            bigpid = pid.ljust(16, "\0")
            temp_key = Alf::pc1(keyvec1, bigpid, false)            
            temp_key_sum = 0
            for i in 0...temp_key.length do
                temp_key_sum += temp_key[i].ord
            end
            temp_key_sum &= 0xff
            found_key = false
            for i in 0...count do
                verification, size, type, cksum = data[i*0x30...i*0x30+0x10].unpack('NNNCxxx')
                cookie = data[i*0x30+0x10...i*0x30+0x30]
                if cksum == temp_key_sum
                    cookie = Alf::pc1(temp_key, cookie)
                    ver,flags = cookie.unpack('L>L>')
                    finalkey = cookie.slice(8, 16)
                    expiry,expiry2 = cookie.slice(24, 8).unpack('L>L>')
                    if verification == ver && (flags & 0x1F) == 1
                        found_key = finalkey
                        break 
                    end
                end
            end
            if found_key != false 
                break
            end
        end

        if found_key == nil # no PID 
            # TODO : not found key
        end

        return [found_key, pid]
    end

end

def remove_drm(infile, token, do_overwrite)
    puts "Processing book file:" + infile
    header = File.open(infile).sysread(68)
    if header[60...68] == 'BOOKMOBI'
        format = 'mobi'
    end

    mb = MobiBook.new(infile)
    if mb.sect[0xC...0xC + 2] == '\0\0'
        format = 'nodrm-mobi'
    end
    puts 'Detected input file format:' + format

    pidlist = []
    if token.length == 16
        puts "Serial number:" + token
        serial = token
    else 
        printf("Unrecognize size:%d\n", token.length)
    end

    title = mb.get_book_title()
    puts "book title:" + title
    md1, md2 = mb.get_pid_meta_info()
    Genpid::get_kindle_pid(pidlist, md1, md2, serial)    
    print "Using PIDs:", pidlist, "\n"

    mb.process_book(pidlist)
    
    # creat drm removed file 
    f = File.new(title+"-nodrm"+".mobi", "w")
    f.syswrite(mb.mobi_data)
end

def argv_check
    serial = ""
    file = ""
    $s_index = false
    $f_index = false
    $*.each { |x|
        if x == '-s'
            $s_index = true
            $f_index = false
        elsif x == '-f'
            $f_index = true
            $s_index = false
        elsif x[0] != '-'
            if $s_index == true
                serial << x
            elsif $f_index == true 
                file << x
            end
        else
            puts "Usage:"
            puts "-s serial number of your kindle device"
            puts "-f the file to decrypt"
            exit false
        end
    }

    if file == "" || serial == ""
        puts "Pls. input the file name or kindle serial number"
        exit false
    end
    if !File.exist?(file)
        puts "No such file"
        exit false
    end
    return file, serial
end

# Here we go.
file, serial = argv_check()
remove_drm(file, serial, 0)

