import os
from datetime import datetime,timedelta
import requests
from os import listdir
from os.path import isfile, join
mypath = '/home/joshua/Documents/' #Directory Path

onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))] #Lists directory contents as well checks if the file exists, if it doesent, dont add
print(onlyfiles)


Timelist = []
for Time in onlyfiles:
    UnixTime = os.path.getmtime(mypath + f'{Time}') #Time of modify
    ConvertedTime = str(datetime.fromtimestamp(UnixTime)) #Converts UNIX into Delta Time
    print(ConvertedTime)
    Timelist.append(ConvertedTime)

File_Time_Dict_ALL = dict(zip(onlyfiles,Timelist))

print(File_Time_Dict_ALL)


last_hours_date_time = datetime.now() - timedelta(hours = 4) #We are currently using Delta time, UNIX for what files to check, it will only check
#files in the past 4 hours that have been created or modified.
print(last_hours_date_time)




print(Timelist)





file = input(' File Name ')

url = 'https://www.virustotal.com/vtapi/v2/file/scan'

Key = {'apikey': 'b0fbe2a9eda8ca56c4e9e611b1c38eefdd1d759ab3c0af6aec93a794ae7d897e'}

files = {'file': (file, open(file, 'rb'))}

response = requests.post(url, files=files, params=Key)

print(response.json())