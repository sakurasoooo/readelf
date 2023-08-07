import re
line_start = 471
line_end = 487

# with open('/usr/include/elf.h','r') as source:
#     lines = source.readlines()
#     with open('./ouput.c','w') as output:
#         output.write("switch(code)\n{\n")
#         for line in lines[(line_start - 1):(line_end - 1)]:
#             matchCase = re.match(r'#define (?P<value>\w+).*(?=\* )\* (?P<architecture>.+) \*(?<= \*).*', line)
#             if matchCase :
#                 output.write('\tcase {}:\n\t\tprintf("{}\\n");\n\t\tbreak;\n'.format(matchCase .group('value'),matchCase .group('architecture')))
#         output.write('\tdefault: \n\t\tprintf("Unknown\\n");\n\t\tbreak;\n}\n')

with open('/usr/include/elf.h', 'r') as source:
    lines = source.readlines()
    with open('./ouput.c', 'w') as output:
        output.write("switch(code)\n{\n")
        for line in lines[(line_start - 1):(line_end - 1)]:
            matchCase = re.match(
                r'#define (?P<value>\w+).*(?=\* )\* (?P<architecture>.+) \*(?<= \*).*', line)
            if matchCase:
                output.write('\tcase {}:\n\t\tprintf("%-18s","{}");\n\t\tbreak;\n'.format(
                    matchCase .group('value'), matchCase .group('value')))
        output.write('\tdefault: \n\t\tprintf("Unknown\\n");\n\t\tbreak;\n}\n')
