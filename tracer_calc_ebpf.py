# FILE: tracer.py

def parse_data(file_path):
    with open(file_path, 'r') as file:
        data = file.read().strip().split('\n\n\n')
    
    times = {
        'cls_bpf_classify': [],
        'tcf_classify': [],
        'tc_run': [],
        'netif_receive_skb': []
    }
    
    for group in data:
        lines = group.strip().split('\n')
        if len(lines) == 4:
            times['cls_bpf_classify'].append(float(lines[0]))
            times['tcf_classify'].append(float(lines[1]))
            times['tc_run'].append(float(lines[2]))
            times['netif_receive_skb'].append(float(lines[3]))
    
    return times

def print_times(times):
    for func, values in times.items():
        print(f"Times for {func}: {values}")

def calculate_average(times, key):
    values = times.get(key, [])
    if not values:
        return 0
    return sum(values) / len(values)

def main():
    file_path = 'tracer.py'
    times = parse_data(file_path)
    print_times(times)
    avg_bpf_classify = calculate_average(times, 'cls_bpf_classify')
    avg_tc_run = calculate_average(times, 'tcf_classify')
    print(f"Percent cls_bpf_classify spends in tcf_classify: {avg_bpf_classify / avg_tc_run * 100:.2f}%")

if __name__ == "__main__":
    main()