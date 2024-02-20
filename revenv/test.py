import r2pipe

r = r2pipe.open("./example-bins/hello_world.out")
print(r.cmd("pd 10"))
# print(r.cmd("aaaa"))
# print(r.cmd("pdfj @@f"))
