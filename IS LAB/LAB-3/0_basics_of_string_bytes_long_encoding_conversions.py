from Crypto.Util.number import bytes_to_long, long_to_bytes

msg = "ABC123"

# String
print("1. String:")
print(msg)
print(type(msg))

# String -> Bytes
data = msg.encode()
print("\n2. Encode:")
print(data)
print(type(data))

# Character -> ASCII
print("\n3. ASCII:")
for ch in msg:
    print(ch, "->", ord(ch))

# Bytes -> Hex
h = data.hex()
print("\n4. Hex:")
print(h)
print(type(h))

# Hex -> Bytes
data2 = bytes.fromhex(h)
print("\n5. From Hex:")
print(data2)

# Bytes -> Long
m = bytes_to_long(data)
print("\n6. Bytes to Long:")
print(m)

# Long -> Bytes
data3 = long_to_bytes(m)
print("\n7. Long to Bytes:")
print(data3)

# Bytes -> String
msg2 = data3.decode()
print("\n8. Decode:")
print(msg2)