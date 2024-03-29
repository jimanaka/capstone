strings = []
strings.append("                   | /* r2dec pseudo code output */")
strings.append("                   | /* binex1.out @ 0x80492ef */")
strings.append("    0x080492ef     | int32_t main (char ** argv) {")

payload = []
for s in strings:
    items = s.split("|")
    address = items[0].strip()
    if len(items) > 1:
        code = "".join(items[1:])
        if len(code) > 0:
            code = code[1:]
    else:
        code = ""
    payload.append({"address": address, "code": code})

print(payload)
