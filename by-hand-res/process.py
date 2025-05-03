import sys
import statistics

def extract_num(string):
    unit = string.find("kB/sec")
    eq = string.find("=")
    return float(string[eq+2:unit])

if (len(sys.argv) < 2):
    exit(-1)

data = []
rand_read = []
rand_write = []

with open(sys.argv[1], 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line.strip()
        if ("Children see" in line):
            if ("random readers" in line):
                rand_read.append(extract_num(line))
            elif ("random writers" in line):
                rand_write.append(extract_num(line))

print("Read avg throughput: {}".format(sum(rand_read) / len(rand_read)))
print("Read avg stdev: {}".format(statistics.stdev(rand_read)))
print("Write avg throughput: {}".format(sum(rand_write) / len(rand_write)))
print("Write avg stdev: {}".format(statistics.stdev(rand_write)))


