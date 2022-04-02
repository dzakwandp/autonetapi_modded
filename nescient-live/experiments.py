import numpy as np
import pandas as pd

from apiclient import report
from elasticclient import get_netflow_resampled, get_netflow_data_at_nearest_time
from utils import getprotobynumber

normal_start_time = "2021-03-20T07:06:00.000Z"
normal_end_time = "2021-03-20T07:11:00.000Z"
dos_start_time = "2021-03-20T07:41:00.000Z"
dos_end_time = "2021-03-20T07:46:00.000Z"
spoofed_dos_start_time = "2021-03-20T07:48:03.000Z"
spoofed_dos_end_time = "2021-03-20T07:54:03.000Z"

#custom_start_time = "2021-06-12T07:02:03.000Z" 
#custom_end_time = "2021-06-12T07:07:03.000Z"

#custom_start_time = "2021-06-17T02:15:03.000Z" 
#custom_end_time = "2021-06-17T02:35:03.000Z"

custom_start_time = "2021-06-23T08:20:03.000Z" 
custom_end_time = "2021-06-23T08:50:03.000Z"

normal_data_object_array = get_netflow_resampled(start_time=normal_start_time, end_time=normal_end_time)
dos_data_object_array = get_netflow_resampled(start_time=dos_start_time, end_time=dos_end_time)
spoofed_dos_data_object_array = get_netflow_resampled(start_time=spoofed_dos_start_time, end_time=spoofed_dos_end_time)

custom_time_array = get_netflow_resampled(start_time=custom_start_time, end_time=custom_end_time)


# prepare elastic data

data_to_be_used = custom_time_array # switch this variable for other case

print("The time shown in UTC +0. \n")
print(custom_start_time)
print(custom_end_time)

A1_all = []
A2_all = []
A3_all = []
A4_all = []

for bucket in data_to_be_used:
    A1_all.append([
        bucket['key'],
        bucket['packets']['value']
    ])
    A2_all.append([
        bucket['key'],
        bucket['USIP']['value']
    ])
    A3_all.append([
        bucket['key'],
        0 if bucket['USIP']['value'] == 0 or bucket['UDIP']['value'] == 0 else bucket['USIP']['value'] / bucket['UDIP']['value']
    ])
    A4_all.append([
        bucket['key'],
        0 if bucket['USIP']['value'] == 0 or bucket['UPR']['value'] == 0 else bucket['USIP']['value'] / bucket['UPR']['value']
    ])


A_all = (
    pd.DataFrame(A1_all),
    pd.DataFrame(A2_all),
    pd.DataFrame(A3_all),
    pd.DataFrame(A4_all)
)

Threshold_all = []
N_all = []
beta_all = []

j_to_end = range(len(A1_all))

for A in A_all:
    # Init values
    K = 1
    beta = 1.5
    j = 0
    T = 3
    current_threshold_array = list()
    current_N_array = list()
    current_beta_array = list()

    A_list = A.iloc[:, 1].to_list()
    safe_A_list = [*A_list, *([0] * K * T)]

    current_moving_A = A.iloc[j: j+K, 1].to_list()
    current_moving_mean = np.mean(current_moving_A)
    current_moving_variance = np.std(current_moving_A)
    current_threshold = (current_moving_mean + current_moving_variance) * beta

    current_threshold_array.append([j, current_threshold])
    current_beta_array.append([j, beta])

    # while j <= K*T-1 and j < len(A1_all.iloc[:, 0].to_list()):
    while j < len(A1_all):
        if j < 0 and j % K*T == 0:
            beta = 1.5
            current_moving_A = safe_A_list[j: j+K]
            current_moving_mean = np.mean(current_moving_A)
            current_moving_variance = np.std(current_moving_A)
            current_threshold = (current_moving_mean + current_moving_variance) * beta

            current_threshold_array.append([j, current_threshold])
            current_beta_array.append([j, beta])
            if safe_A_list[j:j+1][0] > current_threshold:
                current_N_array.append([j, True])
            else:
                current_N_array.append([j, False])
        else:
            if safe_A_list[j:j+1][0] > current_threshold:
                current_N_array.append([j, True])
            else:
                current_N_array.append([j, False])
            j = j + 1
            current_j = j
            previous_j = j - 1
            previous_moving_mean = np.mean(safe_A_list[previous_j: previous_j+K])
            current_moving_mean = np.mean(safe_A_list[current_j: current_j+K])
            if current_moving_mean > 2 * previous_moving_mean:
                beta = beta + 0.5
                current_threshold = (current_moving_mean + np.std(safe_A_list[current_j: current_j+K])) / beta
            else:
                beta = beta - 0.5
                if beta < 1.0:
                    beta = 1
                current_threshold = (current_moving_mean + np.std(safe_A_list[current_j: current_j+K])) * beta
            current_threshold_array.append([current_j, current_threshold])
            current_beta_array.append([j, beta])

    Threshold_all.append(current_threshold_array)
    N_all.append(current_N_array)
    beta_all.append(current_beta_array)


for idx in j_to_end:
    if N_all[0][idx][1] is True and N_all[1][idx][1] is True and N_all[2][idx][1] is True and N_all[3][idx][1] is True:
        timestamp = int(str(data_to_be_used[idx]['key'])[:-3])
        positive_traffic = get_netflow_data_at_nearest_time(timestamp)
        print("POSITIVE", timestamp, positive_traffic)

    else:
        timestamp = int(str(data_to_be_used[idx]['key'])[:-3])
        negative_traffic = get_netflow_data_at_nearest_time(timestamp)
        print("negative: ", timestamp, negative_traffic)

        #report(
        #    positive_traffic['source_ipv4_address'],
        #    positive_traffic['destination_ipv4_address'],
        #    positive_traffic['destination_transport_port'],
        #    getprotobynumber(positive_traffic['protocol_identifier']),
        #    timestamp
        #)



