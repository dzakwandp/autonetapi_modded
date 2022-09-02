import numpy as np
from numpy.lib.function_base import select
from joblib import dump, load
import pandas as pd
from datetime import timezone, datetime, timedelta
import schedule
import time
import sys

# import sqlite3
import sqlalchemy as db
import hashlib

from sqlalchemy import func, text
from sqlalchemy.sql.expression import column, table

from apiclient import report, detection_log
from elasticclient import get_netflow_resampled, get_netflow_data_at_nearest_time
from utils import getprotobynumber

# Check database

thetime = datetime.now().strftime("%Y%m%d_%H%M%S")

engine = db.create_engine('sqlite:///detector_' + thetime + '.sqlite')
connection = engine.connect()
metadata = db.MetaData()
metadata.bind = engine

detector = db.Table('detector', metadata,
              db.Column('Id', db.Integer, primary_key=True, autoincrement=True),
              db.Column('timestamp', db.DateTime),
              db.Column('src_ip', db.String(255), nullable=False),
              db.Column('dst_ip', db.String(255), nullable=False),
              db.Column('dst_port', db.String(255), nullable=False),
              db.Column('protocol', db.String(255), nullable=False),
              db.Column('detection_status', db.String(32), nullable=False),
              db.Column('hash', db.String(256), nullable=False, unique=True)
              )

metadata.create_all(engine) #Creates the table

#detector = db.Table('detector', metadata, autoload=True, autoload_with=engine)

#conn = engine.connect()

# Attack detection

def attack_detection(time_start):
    
    # Hash with SHA
    def encrypt_hash(hash_string):
        sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature


    # dataset scan time interval from the current time program being executed
    #dataset_time_range = 70
    dataset_time_offset = 3

    #delta = timedelta(seconds=(dataset_time_range + dataset_time_offset))
    last_delta = timedelta(seconds=dataset_time_offset)

    current_time = datetime.now()
    time_now = (current_time).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    time_before = (time_start).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    #print(time_before)
    #print(time_now)

    live_data_array = get_netflow_resampled(start_time=time_before, end_time=time_now)

    # print("[nescient] Scanning whether attack is detected or not ...")
    print("[nescient] Scanning for anomalies : ", time_before, "to", time_now)

    # prepare elastic data

    data_to_be_used = live_data_array # switch this variable for other case

    # try:
    #     A1_all = []
    #     A2_all = []
    #     A3_all = []
    #     A4_all = []

    #     for bucket in data_to_be_used:
    #         A1_all.append([
    #             bucket['key'],
    #             bucket['packets']['value']
    #         ])
    #         A2_all.append([
    #             bucket['key'],
    #             bucket['USIP']['value']
    #         ])
    #         A3_all.append([
    #             bucket['key'],
    #             0 if bucket['USIP']['value'] == 0 or bucket['UDIP']['value'] == 0 else bucket['USIP']['value'] / bucket['UDIP']['value']
    #         ])
    #         A4_all.append([
    #             bucket['key'],
    #             0 if bucket['USIP']['value'] == 0 or bucket['UPR']['value'] == 0 else bucket['USIP']['value'] / bucket['UPR']['value']
    #         ])


    #     A_all = (
    #         pd.DataFrame(A1_all),
    #         pd.DataFrame(A2_all),
    #         pd.DataFrame(A3_all),
    #         pd.DataFrame(A4_all)
    #     )

    #     Threshold_all = []
    #     N_all = []
    #     beta_all = []

    #     j_to_end = range(len(A1_all))

    #     for A in A_all:
    #         # Init values
    #         K = 1
    #         beta = 1.5
    #         j = 0
    #         T = 3
    #         current_threshold_array = list()
    #         current_N_array = list()
    #         current_beta_array = list()

    #         A_list = A.iloc[:, 1].to_list()
    #         safe_A_list = [*A_list, *([0] * K * T)]

    #         current_moving_A = A.iloc[j: j+K, 1].to_list()
    #         current_moving_mean = np.mean(current_moving_A)
    #         current_moving_variance = np.std(current_moving_A)
    #         current_threshold = (current_moving_mean + current_moving_variance) * beta

    #         current_threshold_array.append([j, current_threshold])
    #         current_beta_array.append([j, beta])

    #         # while j <= K*T-1 and j < len(A1_all.iloc[:, 0].to_list()):
    #         while j < len(A1_all):
    #             if j < 0 and j % K*T == 0:
    #                 beta = 1.5
    #                 current_moving_A = safe_A_list[j: j+K]
    #                 current_moving_mean = np.mean(current_moving_A)
    #                 current_moving_variance = np.std(current_moving_A)
    #                 current_threshold = (current_moving_mean + current_moving_variance) * beta

    #                 current_threshold_array.append([j, current_threshold])
    #                 current_beta_array.append([j, beta])
    #                 if safe_A_list[j:j+1][0] > current_threshold:
    #                     current_N_array.append([j, True])
    #                 else:
    #                     current_N_array.append([j, False])
    #             else:
    #                 if safe_A_list[j:j+1][0] > current_threshold:
    #                     current_N_array.append([j, True])
    #                 else:
    #                     current_N_array.append([j, False])
    #                 j = j + 1
    #                 current_j = j
    #                 previous_j = j - 1
    #                 previous_moving_mean = np.mean(safe_A_list[previous_j: previous_j+K])
    #                 current_moving_mean = np.mean(safe_A_list[current_j: current_j+K])
    #                 if current_moving_mean > 2 * previous_moving_mean:
    #                     beta = beta + 0.5
    #                     current_threshold = (current_moving_mean + np.std(safe_A_list[current_j: current_j+K])) / beta
    #                 else:
    #                     beta = beta - 0.5
    #                     if beta < 1.0:
    #                         beta = 1
    #                     current_threshold = (current_moving_mean + np.std(safe_A_list[current_j: current_j+K])) * beta
    #                 current_threshold_array.append([current_j, current_threshold])
    #                 current_beta_array.append([j, beta])

    #         Threshold_all.append(current_threshold_array)
    #         N_all.append(current_N_array)
    #         beta_all.append(current_beta_array)


    #     for idx in j_to_end:
    #         if N_all[0][idx][1] is True and N_all[1][idx][1] is True and N_all[2][idx][1] is True and N_all[3][idx][1] is True:
    #             try:
    #                 timestamp = int(str(data_to_be_used[idx]['key'])[:-3])
    #                 positive_traffic = get_netflow_data_at_nearest_time(timestamp)
    #                 #print('[POSITIVE]', timestamp, positive_traffic)

    #                 check_string = "{}_{}_{}_{}_{}".format(
    #                         timestamp,
    #                         positive_traffic['source_ipv4_address'],
    #                         positive_traffic['destination_ipv4_address'],
    #                         positive_traffic['destination_transport_port'],
    #                         getprotobynumber(positive_traffic['protocol_identifier']))                    
    #                 hash_data = encrypt_hash(check_string)

    #                 # select the data
    #                 q = detector.select().where(detector.c.hash == hash_data)
    #                 count = connection.execute(q).scalar()

    #                 if count is None:
    #                     print('[POSITIVE]', timestamp, positive_traffic)

    #                     # yes this is for hashing                    
    #                     message_log = "POSITIVE src: {}, dest: {}, dest_port: {}, L4_proto: {}, time: {}".format(
    #                         positive_traffic['source_ipv4_address'],
    #                         positive_traffic['destination_ipv4_address'],
    #                         positive_traffic['destination_transport_port'],
    #                         getprotobynumber(positive_traffic['protocol_identifier']),
    #                         timestamp
    #                     )
                        
    #                     # add sqlite record
    #                     # time format example: 2021-06-12T13:02:45.039252+07:00"
    #                     add_record = detector.insert().values(
    #                         timestamp=datetime.fromtimestamp(timestamp), 
    #                         src_ip = positive_traffic['source_ipv4_address'],
    #                         dst_ip = positive_traffic['destination_ipv4_address'],
    #                         dst_port = positive_traffic['destination_transport_port'],
    #                         protocol = getprotobynumber(positive_traffic['protocol_identifier']),
    #                         detection_status = 'POSITIVE',
    #                         hash = hash_data)

    #                     conn = engine.connect()
    #                     result = connection.execute(add_record)

    #                     detection_log(
    #                         datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f%z"), 'Detection', 'POSITIVE', message_log, 'Anonymous')

    #                     report(
    #                         positive_traffic['source_ipv4_address'],
    #                         positive_traffic['destination_ipv4_address'],
    #                         positive_traffic['destination_transport_port'],
    #                         getprotobynumber(positive_traffic['protocol_identifier']),
    #                         timestamp
    #                     )
    #                 else:
    #                     print("Data exists. This record will not be saved or reported.")
                    
    #             except Exception as e:
    #                 print(e)

    #         else:
    #             try:
    #                 timestamp = int(str(data_to_be_used[idx]['key'])[:-3])
    #                 negative_traffic = get_netflow_data_at_nearest_time(timestamp)
    #                 #print('[negative]', timestamp, negative_traffic)
                    
    #                 check_string = "{}_{}_{}_{}_{}".format(
    #                         timestamp,
    #                         negative_traffic['source_ipv4_address'],
    #                         negative_traffic['destination_ipv4_address'],
    #                         negative_traffic['destination_transport_port'],
    #                         getprotobynumber(negative_traffic['protocol_identifier']))
                    
    #                 hash_data = encrypt_hash(check_string)

    #                 # select the data
    #                 q = detector.select().where(detector.c.hash == hash_data)
    #                 conn = engine.connect()
    #                 count = connection.execute(q).scalar()

    #                 if count is None:
    #                     print('[negative]', timestamp, negative_traffic)

    #                     message_log = "NEGATIVE src: {}, dest: {}, dest_port: {}, L4_proto: {}, time: {}".format(
    #                         negative_traffic['source_ipv4_address'],
    #                         negative_traffic['destination_ipv4_address'],
    #                         negative_traffic['destination_transport_port'],
    #                         getprotobynumber(negative_traffic['protocol_identifier']),
    #                         timestamp
    #                     )

    #                     add_record = detector.insert().values(
    #                         timestamp=datetime.fromtimestamp(timestamp), 
    #                         src_ip = negative_traffic['source_ipv4_address'],
    #                         dst_ip = negative_traffic['destination_ipv4_address'],
    #                         dst_port = negative_traffic['destination_transport_port'],
    #                         protocol = getprotobynumber(negative_traffic['protocol_identifier']),
    #                         detection_status = 'NEGATIVE',
    #                         hash = hash_data)

    #                     conn = engine.connect()
    #                     result = connection.execute(add_record)

    #                     detection_log(
    #                         datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f%z"), 'Detection', 'NEGATIVE', message_log, 'Anonymous')

    #                 else:
    #                     print("Data exists. This record will not be saved or reported.")

    #             except Exception as e:
    #                 print(e)
                    
    # except Exception as e:
    #     print(e)

print("[nescient] Attack detector started. Detection will be started shortly.")

# Automatically poll from ELK stack server and analyze every n seconds
time_start = datetime.now()

schedule.every(3).seconds.do(attack_detection, time_start)

while True:
    try:
        schedule.run_pending()
    except KeyboardInterrupt:
        sys.exit(0)



