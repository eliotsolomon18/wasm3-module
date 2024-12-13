# FILE: tracer.py

def parse_data(file_path):
    with open(file_path, 'r') as file:
        data = file.read().strip().split('\n\n')
    
    times = {
        'skb_copy_bits': [],
        'm3_CallV': [],
        'm3_GetResultsV': [],
        'nf_filter': [],
        'netif_receive_skb': []
    }
    
    for group in data:
        lines = group.strip().split('\n')
        if len(lines) == 6:
            skb_copy_bits_combined = float(lines[0]) + float(lines[3])
            times['skb_copy_bits'].append(skb_copy_bits_combined)
            times['m3_CallV'].append(float(lines[1]))
            times['m3_GetResultsV'].append(float(lines[2]))
            times['nf_filter'].append(float(lines[4]))
            times['netif_receive_skb'].append(float(lines[5]))
    
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
    avg_skb_copy_bits = calculate_average(times, 'skb_copy_bits')
    avg_m3_all = calculate_average(times, 'm3_CallV') + calculate_average(times, 'm3_GetResultsV')
    avg_nf_filter = calculate_average(times, 'nf_filter')
    avg_netif_receive_skb = calculate_average(times, 'netif_receive_skb')
    print(f"Average time for nf_filter: {avg_nf_filter} us")
    print(f"Average time for netif_receive_skb: {avg_netif_receive_skb} us")
    print(f"Percent nf_filter spends in netif_receive_skb: {avg_nf_filter / avg_netif_receive_skb * 100:.2f}%")
    print(f"Percent skb_copy_bits spends in netif_receive_skb: {avg_skb_copy_bits / avg_netif_receive_skb * 100:.2f}%")
    print(f"Percent m3 spends in netif_receive_skb: {avg_m3_all / avg_netif_receive_skb * 100:.2f}%")
    print(f"Percent of time spent doing wasm stuff (copy in, call, copy out): {(avg_m3_all + avg_skb_copy_bits) / avg_nf_filter * 100:.2f}%")

if __name__ == "__main__":
    main()