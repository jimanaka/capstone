lists = [{"l1": ["0x1", "0x2", "ebp", "esp"]}, {"l1": ["0x5", "ebp", "rax"]}]

merged_list = []
for gadget in lists:
    merged_list.extend(item for item in gadget["l1"] if not item.startswith("0x"))

print(merged_list)
