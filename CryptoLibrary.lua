-- SHA256.lua
-- A Lua implementation of SHA256 hashing algorithm

local CryptoModule = {}

local SHA256 = {}

local bit32 = bit32 or require("bit32")

local function rightRotate(x, n)
	assert(x, "Invalid argument #1 to 'rightRotate' (number expected, got nil)")
	assert(n, "Invalid argument #2 to 'rightRotate' (number expected, got nil)")
	return bit32.rrotate(x, n)
end

local function preprocess(msg)
	local l = #msg * 8
	msg = msg .. "\128" .. string.rep("\0", 63 - ((#msg + 8) % 64))
	msg = msg .. string.pack(">I8", l)
	return msg
end

local function parse(msg) --ERRORS BECAUSE CHUNKSIZE WONT ALLOW STRINGS UNDER 64 CHARACTERS IN LENGTH
	local M = {}
	local chunkSize = 64
	for i = 1, #msg, chunkSize do
		local chunk = msg:sub(i, i + chunkSize - 1)
		local words = {}
		for j = 1, chunkSize, 4 do
			local word = string.unpack(">I4", chunk:sub(j, j + 3))
			table.insert(words, word)
		end
		table.insert(M, words)
	end
	return M
end

local function sha256(msg)
	assert(type(msg) == "string", "Invalid argument #1 to 'sha256' (string expected)")
	assert(#msg >= 64, "Invalid argument #1 to 'sha256' (string length must be at least 64)")

	local K = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
		0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
		0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
		0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}

	local H = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	}

	msg = preprocess(msg)
	local M = parse(msg)

	for i, words in ipairs(M) do
		local W = {}
		for j = 1, 16 do
			W[j] = words[j]
		end
		for j = 17, 64 do
			local s0 = bit32.bxor(rightRotate(W[j-15], 7), rightRotate(W[j-15], 18), bit32.rshift(W[j-15], 3))
			local s1 = bit32.bxor(rightRotate(W[j-2], 17), rightRotate(W[j-2], 19), bit32.rshift(W[j-2], 10))
			W[j] = bit32.band((W[j-16] + s0 + W[j-7] + s1), 0xFFFFFFFF)
		end

		local a, b, c, d, e, f, g, h = table.unpack(H)

		for j = 1, 64 do
			local S1 = bit32.bxor(rightRotate(e, 6), rightRotate(e, 11), rightRotate(e, 25))
			local ch = bit32.bxor(bit32.band(e, f), bit32.band(bit32.bnot(e), g))
			local temp1 = bit32.band((h + S1 + ch + K[j] + W[j]), 0xFFFFFFFF)
			local S0 = bit32.bxor(rightRotate(a, 2), rightRotate(a, 13), rightRotate(a, 22))
			local maj = bit32.bxor(bit32.band(a, b), bit32.band(a, c), bit32.band(b, c))
			local temp2 = bit32.band((S0 + maj), 0xFFFFFFFF)

			h = g
			g = f
			f = e
			e = bit32.band((d + temp1), 0xFFFFFFFF)
			d = c
			c = b
			b = a
			a = bit32.band((temp1 + temp2), 0xFFFFFFFF)
		end

		H[1] = bit32.band((H[1] + a), 0xFFFFFFFF)
		H[2] = bit32.band((H[2] + b), 0xFFFFFFFF)
		H[3] = bit32.band((H[3] + c), 0xFFFFFFFF)
		H[4] = bit32.band((H[4] + d), 0xFFFFFFFF)
		H[5] = bit32.band((H[5] + e), 0xFFFFFFFF)
		H[6] = bit32.band((H[6] + f), 0xFFFFFFFF)
		H[7] = bit32.band((H[7] + g), 0xFFFFFFFF)
		H[8] = bit32.band((H[8] + h), 0xFFFFFFFF)
	end

	local hash = ""
	for i = 1, 8 do
		hash = hash .. string.format("%08x", H[i])
	end
	return hash
end

-- MD5.lua
-- Module for generating MD5 hashes

local MD5 = {}

-- Constants for MD5 calculation
local k = {}
local r = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21}

for i = 1, 64 do
	k[i] = math.floor((2^32) * math.abs(math.sin(i + 1)))
end

local function leftrotate(x, c)
	return bit32.lrotate(x, c)
end

local function to_bytes_le(str)
	local bytes = {}
	for i = 1, #str do
		table.insert(bytes, str:byte(i))
	end
	return bytes
end

local function to_hex_string(bytes)
	local hex_str = ""
	for _, byte in ipairs(bytes) do
		hex_str = hex_str .. string.format("%02x", byte)
	end
	return hex_str
end

local function md5_transform(buf, bytes)
	local a, b, c, d = buf[1], buf[2], buf[3], buf[4]

	for i = 1, 64 do
		local f, g
		if i < 16 then
			f = bit32.bor(bit32.band(b, c), bit32.band(bit32.bnot(b), d))
			g = i
		elseif i < 32 then
			f = bit32.bor(bit32.band(d, b), bit32.band(bit32.bnot(d), c))
			g = (5 * i + 1) % 16
		elseif i < 48 then
			f = bit32.bxor(b, bit32.bxor(c, d))
			g = (3 * i + 5) % 16
		else
			f = bit32.bxor(c, bit32.bor(b, bit32.bnot(d)))
			g = (7 * i) % 16
		end
		local temp = d
		d = c
		c = b
		b = b + leftrotate((a + f + k[i] + bytes[g + 1]) % 2^32, r[i])
		a = temp
	end

	buf[1] = (buf[1] + a) % 2^32
	buf[2] = (buf[2] + b) % 2^32
	buf[3] = (buf[3] + c) % 2^32
	buf[4] = (buf[4] + d) % 2^32
end

function MD5.hash(input)
	local bytes = to_bytes_le(input)
	local bit_len = #bytes * 8

	-- Padding
	table.insert(bytes, 0x80)
	while (#bytes % 64) ~= 56 do
		table.insert(bytes, 0)
	end

	-- Append length
	for i = 1, 8 do
		table.insert(bytes, bit32.band(bit32.rshift(bit_len, i * 8), 0xFF))
	end

	local buf = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}

	for i = 1, #bytes, 64 do
		local chunk = {}
		for j = 1, 64 do
			chunk[j] = bytes[i + j] or 0
		end
		md5_transform(buf, chunk)
	end

	return to_hex_string({
		bit32.band(buf[1], 0xFF), bit32.band(bit32.rshift(buf[1], 8), 0xFF), bit32.band(bit32.rshift(buf[1], 16), 0xFF), bit32.band(bit32.rshift(buf[1], 24), 0xFF),
		bit32.band(buf[2], 0xFF), bit32.band(bit32.rshift(buf[2], 8), 0xFF), bit32.band(bit32.rshift(buf[2], 16), 0xFF), bit32.band(bit32.rshift(buf[2], 24), 0xFF),
		bit32.band(buf[3], 0xFF), bit32.band(bit32.rshift(buf[3], 8), 0xFF), bit32.band(bit32.rshift(buf[3], 16), 0xFF), bit32.band(bit32.rshift(buf[3], 24), 0xFF),
		bit32.band(buf[4], 0xFF), bit32.band(bit32.rshift(buf[4], 8), 0xFF), bit32.band(bit32.rshift(buf[4], 16), 0xFF), bit32.band(bit32.rshift(buf[4], 24), 0xFF)
	})
end

local function md5(message)
	local result = MD5.hash(message)
	
	return result
end


SHA256.hash = sha256

CryptoModule.sha256 = SHA256.hash

CryptoModule.md5 = md5

return CryptoModule
