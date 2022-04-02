from datetime import timezone, datetime, timedelta
#import tzinfo

#normal_start_time = "2021-03-20T07:06:00.000Z"
#mytime_timestamp = datetime.strptime(datetime.now(), "%Y-%m-%d")
current_time = datetime.now()
mytime_timestamp = current_time.astimezone(timezone.utc).strftime("%Y-%m-%dT:%H:%M:%S.%f")
delta = timedelta(seconds=50)

time_before = (current_time - delta).astimezone(timezone.utc).strftime("%Y-%m-%dT:%H:%M:%S.%f")[:-3] + "Z"
time_now = mytime_timestamp[:-3] + "Z" 

print(time_before)
print(time_now)

#datetime_obj_utc = mytime_timestamp.replace(tzinfo=timezone('Etc/UTC'))
#datetime_obj_cst = mytime_timestamp.replace(tzinfo=timezone('America/Chicago'))

#s_achieved = datetime_obj_cst
#s_achieved_timezone = datetime_obj_utc

#print(s_achieved_timezone)
#print(s_achieved)
