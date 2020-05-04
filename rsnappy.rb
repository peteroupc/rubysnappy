# Defines two methods, 'snappyCompress' and 'snappyUncompress',
# that compress and decompress byte strings in Snappy format.
#
# NOTE: Adapted by Peter O. (github.com/peteroupc)
# from snappy-js (https://github.com/zhipeng-jia/snappyjs), which is licensed as follows.
# The license and the copyright notice for snappy-js is reproduced below.
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Zhipeng Jia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#####
# Adapted from snappy-js

class SnappyCompressor 
BLOCK_LOG = 16
BLOCK_SIZE = 1 << BLOCK_LOG
INPUT_MARGIN = 15
MAX_HASH_TABLE_BITS = 14
  def initialize(uncompressed) 
    @array = uncompressed
  end
@@globalHashTables = (MAX_HASH_TABLE_BITS + 1).times.map{nil}


def hashFunc (key, hashFuncShift) 
  return (((key * 0x1e35a7bd) & 0xFFFFFFFF) >> hashFuncShift)&0xFFFFFFFF
end

def load32 (array, pos) 
  return array[pos] + (array[pos + 1] << 8) + (array[pos + 2] << 16) + (array[pos + 3] << 24)
end

def equals32 (array, pos1, pos2) 
  return array[pos1] ==array[pos2] &&
         array[pos1 + 1] ==array[pos2 + 1] &&
         array[pos1 + 2] ==array[pos2 + 2] &&
         array[pos1 + 3] ==array[pos2 + 3]
end

def copyBytes (fromArray, fromPos, toArray, toPos, length) 
  for i in 0...length 
    toArray[toPos + i] = fromArray[fromPos + i]
  end
end

def emitLiteral (input, ip, len, output, op) 
  if (len <= 60) 
    output[op] = (len - 1) << 2
    op += 1
  elsif (len < 256) 
    output[op] = 60 << 2
    output[op + 1] = len - 1
    op += 2
  else 
    output[op] = 61 << 2
    output[op + 1] = (len - 1) & 0xff
    output[op + 2] = (len - 1) >> 8
    op += 3
  end
  copyBytes(input, ip, output, op, len)
  return op + len
end

def emitCopyLessThan64 (output, op, offset, len) 
  if (len < 12 && offset < 2048) 
    output[op] = 1 + ((len - 4) << 2) + ((offset >> 8) << 5)
    output[op + 1] = offset & 0xff
    return op + 2
  else 
    output[op] = 2 + ((len - 1) << 2)
    output[op + 1] = offset & 0xff
    output[op + 2] = offset >> 8
    return op + 3
  end
end

def emitCopy (output, op, offset, len) 
  while (len >= 68) 
    op = emitCopyLessThan64(output, op, offset, 64)
    len -= 64
  end
  if (len > 64) 
    op = emitCopyLessThan64(output, op, offset, 60)
    len -= 60
  end
  return emitCopyLessThan64(output, op, offset, len)
end

def compressFragment (input, ip, inputSize, output, op) 
  hashTableBits = 1
  while ((1 << hashTableBits) <= inputSize &&
         hashTableBits <= MAX_HASH_TABLE_BITS) 
    hashTableBits += 1
  end
  hashTableBits -= 1
  hashFuncShift = 32 - hashTableBits

  if (!@@globalHashTables[hashTableBits]) 
    @@globalHashTables[hashTableBits] = (1 << hashTableBits).times.map{0}
  end
  hashTable = @@globalHashTables[hashTableBits]
  for i in 0...hashTable.length 
    hashTable[i] = 0
  end

  ipEnd = ip + inputSize
  baseIp = ip
  nextEmit = ip
  flag = true

  if (inputSize >= INPUT_MARGIN) 
    ipLimit = ipEnd - INPUT_MARGIN

    ip += 1
    nextHash = hashFunc(load32(input, ip), hashFuncShift)

    while (flag) 
      skip = 32
      nextIp = ip
      begin
        ip = nextIp
        hash = nextHash
        bytesBetweenHashLookups = skip >> 5
        skip += 1
        nextIp = ip + bytesBetweenHashLookups
        if (ip > ipLimit) 
          flag = false
          break
        end
        nextHash = hashFunc(load32(input, nextIp), hashFuncShift)
        candidate = baseIp + hashTable[hash]
        hashTable[hash] = ip - baseIp
      end while (!equals32(input, ip, candidate))

      if (!flag) 
        break
      end

      op = emitLiteral(input, nextEmit, ip - nextEmit, output, op)

      begin 
        base = ip
        matched = 4
        while (ip + matched < ipEnd && input[ip + matched] ==input[candidate + matched]) 
          matched += 1
        end
        ip += matched
        offset = base - candidate
        op = emitCopy(output, op, offset, matched)

        nextEmit = ip
        if (ip >= ipLimit) 
          flag = false
          break
        end
        prevHash = hashFunc(load32(input, ip - 1), hashFuncShift)
        hashTable[prevHash] = ip - 1 - baseIp
        curHash = hashFunc(load32(input, ip), hashFuncShift)
        candidate = baseIp + hashTable[curHash]
        hashTable[curHash] = ip - baseIp
      end while (equals32(input, ip, candidate))
      if (!flag) 
        break
      end
      ip += 1
      nextHash = hashFunc(load32(input, ip), hashFuncShift)
    end
  end
  if (nextEmit < ipEnd) 
    op = emitLiteral(input, nextEmit, ipEnd - nextEmit, output, op)
  end
  return op
end

def putVarint (value, output, op) 
  begin 
    output[op] = value & 0x7f
    value = value >> 7
    if (value > 0) 
      output[op] += 0x80
    end
    op += 1
  end while (value > 0)
  return op
end

def maxCompressedLength() 
  sourceLen = @array.length
  return 32 + sourceLen + (sourceLen / 6).floor
end

def compressToBuffer (outBuffer) 
  array = @array
  length = array.length
  pos = 0
  outPos = 0
  outPos = putVarint(length, outBuffer, outPos)
  while (pos < length) 
    fragmentSize = [length - pos, BLOCK_SIZE].min
    outPos = compressFragment(array, pos, fragmentSize, outBuffer, outPos)
    pos += fragmentSize
  end
  return outPos
end
end

class SnappyDecompressor
WORD_MASK = [0, 0xff, 0xffff, 0xffffff, 0xffffffff]

def initialize(compressed) 
  @array = compressed
  @pos = 0
end


def copyBytes (fromArray, fromPos, toArray, toPos, length) 
  for i in 0...length 
    toArray[toPos + i] = fromArray[fromPos + i]
  end
end

def selfCopyBytes (array, pos, offset, length) 
  for i in 0...length 
    array[pos + i] = array[pos - offset + i]
  end
end


def readUncompressedLength () 
  result = 0
  shift = 0
  while (shift < 32 && @pos < @array.length) 
    c = @array[@pos]
    @pos += 1
    val = c & 0x7f
    if ((((val << shift) & 0xFFFFFFFF) >> shift) != val) 
      return -1
    end
    result |= val << shift
    if (c < 128) 
      return result
    end
    shift += 7
  end
  return -1
end

def uncompressToBuffer (outBuffer) 
  array = @array
  arrayLength = array.length
  pos = @pos
  outPos = 0
  while (pos < array.length) 
    c = array[pos]
    pos += 1
    if ((c & 0x3) == 0) 
      # Literal
      len = (c >> 2) + 1
      if (len > 60) 
        if (pos + 3 >= arrayLength) 
          return false
        end
        smallLen = len - 60
        len = array[pos] + (array[pos + 1] << 8) + (array[pos + 2] << 16) + (array[pos + 3] << 24)
        len = (len & WORD_MASK[smallLen]) + 1
        pos += smallLen
      end
      if (pos + len > arrayLength) 
        return false
      end
      copyBytes(array, pos, outBuffer, outPos, len)
      pos += len
      outPos += len
    else 
      case (c & 0x3) 
        when 1
          len = ((c >> 2) & 0x7) + 4
          offset = array[pos] + ((((c >> 5) & 0xFFFFFFFF) << 8) & 0xFFFFFFFF)
          pos += 1
        when 2
          if (pos + 1 >= arrayLength) 
            return false
          end
          len = (c >> 2) + 1
          offset = array[pos] + (array[pos + 1] << 8)
          pos += 2
        when 3
          if (pos + 3 >= arrayLength) 
            return false
          end
          len = (c >> 2) + 1
          offset = array[pos] + (array[pos + 1] << 8) + (array[pos + 2] << 16) + (array[pos + 3] << 24)
          pos += 4
      end
      if (offset == 0 || offset > outPos) 
        return false
      end
      selfCopyBytes(outBuffer, outPos, offset, len)
      outPos += len
    end
  end
  return true
end
end


############
#  New functions added by Peter O.

def snappyCompress(x)
  x=x.unpack("C*")
  sc=SnappyCompressor.new(x)
  ret=[]
  sc.compressToBuffer(ret)
  return ret.pack("C*")
end

def snappyUncompress(x)
  x=x.unpack("C*")
  sc=SnappyDecompressor.new(x)
  sc.readUncompressedLength()
  ret=[]
  sc.uncompressToBuffer(ret)
  return ret.pack("C*")
end

