from sys import argv
from dataclasses import dataclass
from statistics import median, mean, stdev

@dataclass
class Stat:
    p90: float
    p99: float
    p999: float
    med: float
    avg: float
    dev: float
    dev_p: float
    min_: float
    max_: float

def ratio(base, value):
    return 100.0 / base * value

class Measurements:
    def __init__(self):
        self.p90 = []
        self.p99 = []
        self.p999 = []
        self.med = []
        self.avg = []
        self.min_ = []
        self.max_ = []
        self.reqs = []
        self.time = []
        self.rps = []

    def update(self, p90, p99, p999, med, avg, min_, max_, reqs, time, rps):
        self.p90.append(p90)
        self.p99.append(p99)
        self.p999.append(p999)
        self.med.append(med)
        self.avg.append(avg)
        self.min_.append(min_)
        self.max_.append(max_)
        self.reqs.append(reqs)
        self.time.append(time)
        self.rps.append(rps)

    def stats(self):
        field2stat = {}
        for field in ('p90', 'p99', 'p999', 'med', 'avg', 'min_', 'max_', 'reqs', 'time', 'rps'):
            values = tuple(getattr(self, field))
            values *= 2 if len(values) == 1 else 1
            p90 = values[int((len(values) - 1) * 0.90)]
            p99 = values[int((len(values) - 1) * 0.99)]
            p999 = values[int((len(values) - 1) * 0.999)]
            med = median(values)
            avg = mean(values)
            dev = stdev(values)
            dev_p = ratio(avg, dev)
            min_ = min(values)
            max_ = max(values)
            field2stat[field] = Stat(p90, p99, p999, med, avg, dev, dev_p, min_, max_)
        return field2stat

def print_rows(rows, prefix = 4):
    if len(rows) == 0:
        return
    cols = len(rows[0])
    for row in rows:
        assert(cols == len(row))
    max_cell_len = -1
    for row in rows:
        for cell in row:
            max_cell_len = max((max_cell_len, len(cell)))
    for row in rows:
        print(' ' * prefix, end = '')
        for cell in row:
            print(cell.ljust(max_cell_len + 3), end = '')
        print('') # Newline.

    print('')

s = open(argv[1] if len(argv) > 1 else 'results').read()

cur_ver = None
ver2funcs = {}
for l in s.splitlines():
    if l.startswith('#'):
        cur_ver = l[2:]
        continue
    if cur_ver not in ver2funcs:
        ver2funcs[cur_ver] = {}
    fields = l.split()
    func = fields.pop(0)
    if func not in ver2funcs[cur_ver]:
        ver2funcs[cur_ver][func] = Measurements()
    p90 = float(fields.pop(0))
    p99 = float(fields.pop(0))
    p999 = float(fields.pop(0))
    med = float(fields.pop(0))
    avg = float(fields.pop(0))
    min_ = float(fields.pop(0))
    max_ = float(fields.pop(0))
    reqs = int(fields.pop(0))
    time = float(fields.pop(0))
    rps = int(fields.pop(0))
    ver2funcs[cur_ver][func].update(p90, p99, p999, med, avg, min_, max_, reqs, time, rps)

for ver in ver2funcs:
    print(f'{ver}:')
    for func in ver2funcs[ver]:
        print(f'  {func}:')
        f = ver2funcs[ver][func]
        s = f.stats()
        header = ('', 'MED', 'AVG', 'CV')
        p90 = ('90%', f'{s["p90"].med:.2f}', f'{s["p90"].avg:.2f}', f'±{s["p90"].dev_p:.2f}%')
        p99 = ('99%', f'{s["p99"].med:.2f}', f'{s["p99"].avg:.2f}', f'±{s["p99"].dev_p:.2f}%')
        p999 = ('99.9%', f'{s["p999"].med:.2f}', f'{s["p999"].avg:.2f}', f'±{s["p999"].dev_p:.2f}%')
        prs = ('RPS', f'{s["rps"].med:.2f}', f'{s["rps"].avg:.2f}', f'±{s["rps"].dev_p:.2f}%')
        print_rows((header, p90, p99, p999, prs))
