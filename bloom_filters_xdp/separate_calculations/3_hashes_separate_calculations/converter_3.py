file1 = open("ntua_names", "r")
file2 = open("c_code_3", "w")

bf_size = 236424

file2.write("int myArray[236424];\n")
file2.write("uint64_t result1, result2, result3;\n")
file2.write("uint32_t hash1, hash2, hash3;\n")

counter = 0;
for item in file1:
    fqdn = item.rstrip()
    fqdn = fqdn + ".example.com"
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
    file2.write("hash1 = result1 % " + str(bf_size) + ";\n")
    file2.write("hash2 = result2 % " + str(bf_size) + ";\n")
    file2.write("hash3 = result3 % " + str(bf_size) + ";\n")
    file2.write("myArray[hash1] = 1;\n")
    file2.write("myArray[hash2] = 1;\n")
    file2.write("myArray[hash3] = 1;\n")
    counter = counter + 1

file2.write("for (int i = 0; i < " + str(bf_size) + "; i++) {\n")
file2.write("printf(\"%d\", myArray[i]); }") 
file2.write("\n")
