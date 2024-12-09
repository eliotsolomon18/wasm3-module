import numpy as np

import matplotlib.pyplot as plt

test_cases = ['test_tcp_passthrough_23557', 'test_ipv4_decr_ttl']
throughput_values_1 = [43, 41.9, 38.8, 41.1, 34.9, 44.2, 40, 40, 41.1, 38.9] # mean = 40.39

mean_throughput = np.mean(throughput_values_1)
print(f"The mean throughput is: {mean_throughput}")


# plt.figure(figsize=(10, 5))
# plt.bar(test_cases, average_throughput, color='blue')
# plt.xlabel('Test Case Name')
# plt.ylabel('Average Throughput')
# plt.title('Average Throughput vs Test Case Name')
# plt.show()

######################################################################################################
# test_tcp_passthrough_23557 # [43, 41.9, 38.8, 41.1, 34.9, 44.2, 40, 40, 41.1, 38.9] # mean = 40.39
# test_ipv4_decr_ttl # [40, 40, 40, 40, 40, 40, 40, 40, 40, 40] # mean = 40

# multi trace point
# 41337, 63625, 34095, 53247, 36420, 62596, 69119, 54553, 80345, 70354

# no filter UDP no. packets dropped
# 31084, 13976, 25500, 25302, 15300, 20898, 25952, 32444, 24760, 24401 # Lost/Total = 1145881/40220014

# No filter perf count:net_dev_queue = 114666, 30.03s
# wasm filter perf count:net_dev_queue = 114908, 30.03s

# (Useful) No filter perf count:net_dev_queue BW=38Gbit/s Avg.Throughput=37.8Gbit/s; count = 4,310,088
# (Useful) wasm filter perf count:net_dev_queue BW=38Gbit/s Avg.Throughput=35Gbit/s; count = 4,001,453
# (Useful) ebpf filter perf count:net_dev_queue BW=38Gbit/s Avg.Throughput=37.5Gbit/s; count = 4,281,807

# (Useful) ebpf filter (ttl modify) perf count:net_dev_queue MaxBW=38Gbit/s Avg.Throughput=36.8Gbit/s; trigger_count = 4,205,907
# (Useful) wasm filter (ttl modify) perf count:net_dev_queue MaxBW=38Gbit/s Avg.Throughput=35.5Gbit/s; trigger_count = 4,001,453