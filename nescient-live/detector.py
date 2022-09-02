import numpy as np
from numpy.lib.function_base import select
import pandas as pd
from joblib import dump, load
from datetime import timezone, datetime, timedelta
import schedule
import time
import sys

#import sqlite3
import sqlalchemy as db
import hashlib

from sqlalchemy import func, text
from sqlalchemy.sql.expression import column, table

from apiclient import report, detection_log
from elasticclient import get_netflow_resampled, get_netflow_data_at_nearest_time
from utils import getprotobynumber

#check database
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
               db.Column('detection_status', db.String(255), nullable=False),
               db.Column('hash', db.String(255), nullable=False, unique=True),
               )

metadata.create_all(engine) #create the table

def attack_detection(time_start):
    
    #hash with SHA
    def encrypt_hash(hash_string):
        sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    #dataset scan time interval from the current time program being executed
    dataset_time_offset = 3
    last_delta = timedelta(seconds=dataset_time_offset)
    current_time = datetime.now()
    time_now = (current_time).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    time_before = (time_start).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    live_data_array = get_netflow_resampled(start_time=time_before, end_time=time_now)
    print("[nescient] Scanning for anomalies: ", time_before, "to", time_now)

    #preparing the elastics data
    data_to_be_used = live_data_array

    try:
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
        A_all.to_csv(r'/home/dzak/dataframe.csv')
    
    except Exception as e:
        print(e)
time_start = datetime.now()
schedule.every(3).seconds.do(attack_detection, time_start)