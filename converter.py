file1 = open("netmode_names", "r")
file2 = open("c_code", "w")

bf_size = 95930

file2.write("int myArray[95930];\n")
file2.write("uint64_t result1, result2, result3, result4, result5, result6, result7;\n")
file2.write("uint32_t hash1, hash2, hash3, hash4, hash5, hash6, hash7;\n")

counter = 0;
for item in file1:
    fqdn = item.rstrip()
    file2.write("char myString" + str(counter) + "[253] = \"" + fqdn + "\";\n")
    dots = [pos for pos, char in enumerate(fqdn) if char == '.']
    step = 0
    for chars in dots:
        if step == len(dots) - 1:
            praxi = len(fqdn) - chars - 1
        else:
            praxi = dots[step + 1] - chars - 1
        if praxi < 10:
            file2.write("myString" + str(counter) + "[" + str(chars) + "] = 0x0" + str(praxi) + ";\n")
        else:
            file2.write("myString" + str(counter) + "[" + str(chars) + "] = 0x" + str(praxi) + ";\n")
        step = step + 1
    file2.write("result1 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 0);\n")
    file2.write("result2 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 1);\n")
    file2.write("result3 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 2);\n")
    file2.write("result4 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 3);\n")
    file2.write("result5 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 4);\n")
    file2.write("result6 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 5);\n")
    file2.write("result7 = murmurhash(myString" + str(counter) + ", strlen(myString" + str(counter) + "), 6);\n")
    file2.write("hash1 = result1 % " + str(bf_size) + ";\n")
    file2.write("hash2 = result2 % " + str(bf_size) + ";\n")
    file2.write("hash3 = result3 % " + str(bf_size) + ";\n")
    file2.write("hash4 = result4 % " + str(bf_size) + ";\n")
    file2.write("hash5 = result5 % " + str(bf_size) + ";\n")
    file2.write("hash6 = result6 % " + str(bf_size) + ";\n")
    file2.write("hash7 = result7 % " + str(bf_size) + ";\n")
    file2.write("myArray[hash1] = 1;\n")
    file2.write("myArray[hash2] = 1;\n")
    file2.write("myArray[hash3] = 1;\n")
    file2.write("myArray[hash4] = 1;\n")
    file2.write("myArray[hash5] = 1;\n")
    file2.write("myArray[hash6] = 1;\n")
    file2.write("myArray[hash7] = 1;\n")
    counter = counter + 1

file2.write("for (int i = 0; i < " + str(bf_size) + "; i++) {\n")
file2.write("printf(\"%d\", myArray[i]); }") 
file2.write("\n")
