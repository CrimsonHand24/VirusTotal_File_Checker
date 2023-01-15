import json
import os
import time
from datetime import datetime,timedelta
import requests
from os import listdir
from os.path import isfile, join
import ast
from pprint import pprint



with open('Settings.txt','r') as file:
    file.seek(0)
    Directory =  str(file.read().splitlines()[1].split()[2].strip('"')) # Directory Path
    file.seek(0)
    Hours = int(file.read().splitlines()[3].split()[2].strip('"'))
    file.seek(0)


NOW = datetime.now()
REPORT_FILE_DATE = f'{NOW.year}-{NOW.month}-{NOW.day}-{NOW.hour}-{NOW.minute}'
print(REPORT_FILE_DATE)
with open(f'{REPORT_FILE_DATE}-SCAN','a') as file:
    print(20 * '#' + ' Checking All Files and Organizing ' + 20 * '#')
    Files = [f for f in listdir(Directory) if isfile(
        join(Directory, f))]  # Lists directory contents as well checks if the file exists, if it doesent, dont add

    Timelist = []
    for Time in Files:
        try:
            UnixTime = os.path.getmtime(Directory + f'{Time}')  # Time of modify
            ConvertedTime = str(datetime.fromtimestamp(UnixTime))  # Converts UNIX into Delta Time
            Timelist.append(ConvertedTime)
        except FileNotFoundError:
            print(f'File {Time} not found')

    File_Time_Dict_ALL = dict(zip(Files, Timelist))

    print(File_Time_Dict_ALL)

    last_hours_date_time = datetime.now() - timedelta(
        hours=Hours)  # We are currently using Delta time, UNIX for what files to check, it will only check
    # files in the past 4 hours that have been created or modified.
    print(f'Any files before {last_hours_date_time} wont be check unless specified!')
    Summarized_Dict = {}

    for Summarized in File_Time_Dict_ALL:
        if File_Time_Dict_ALL[Summarized] > str(last_hours_date_time):
            print('Passed')
            Summarized_Dict[Summarized] = File_Time_Dict_ALL.get(
                Summarized)  # Summarized is the Key during the loop, get method will retrieve the value by key name
        else:
            pass
    print(20 * '#' + ' Showing Passed Files ' + 20 * '#')

    print(Summarized_Dict)  # Files that will be scanned

    print(20 * '#' + ' Scanning ' + 20 * '#')

    print(Summarized_Dict)

    for Summarized_File in Summarized_Dict:
        url = "https://www.filescan.io/api/scan/file"

        payload = {'save_preset': 'false',
                   'description': '',
                   'tags': '',
                   'propagate_tags': 'true',
                   'password': '',
                   'is_private': 'true',
                   'skip_whitelisted': ''}
        files = [
            ('file', ('file', open(f'{Directory}' + f"{Summarized_File}", 'rb'), 'application/octet-stream'))
        ]
        headers = {
            'accept': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload, files=files)

        Response_FlowID = response.text  # Json
        # ResponseID = '629370e9054dcf0eca002989' #Malicous
        #ResponseID = '63a4b22ceb21110e8231794f' #Clean Test
        ResponseID = str(ast.literal_eval(Response_FlowID)['flow_id'])  # Gets the JSON code, without needing to parse code
        print(f'Scanning {Summarized_File}, please wait')
        time.sleep(100)
        print('Almost Done!')
        time.sleep(100)
        print('Done Printing Reports')
        def Scan_Retry():
            print(f'Retrying the scan {Summarized_File}, it was not complete, please wait')
            time.sleep(100)
            print('Almost Done!')
            time.sleep(100)
            print('Done Printing Reports')

        url = f"https://www.filescan.io/api/scan/{ResponseID}/report?filter=general&sorting=allSignalGroups%28description%3Aasc%2CaverageSignalStrength%3Adesc%29&sorting=allTags%28tag.name%3Aasc%29&other=emulationGraph"
        # Response id above
        payload = {}
        headers = {
            'accept': 'application/json'
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        print(20 * '#' + ' Non-Summarized Report ' + 20 * '#')
        pprint(response.json())
        print(60 * '#')

        print(20 * '#' + ' Summarized Report ' + 20 * '#')
        Python_Report = dict(json.loads(response.text))
        print(Python_Report)
        while not Python_Report.get('allFinished') == True:
            Scan_Retry()
        for report in Python_Report:
            if report == 'flowId':
                print(f'FlowID = {Python_Report.get(report)}')
                FLOW_ID = Python_Report.get(report)
            if report == 'allFinished':
                ALL_FINISHED = Python_Report.get(report)
                print(f'Report Finished = {Python_Report.get(report)}')
            if report == 'allFilesDownloadFinished':
                print(
                    f'All Files Were Downloaded to Server to Scan? = {Python_Report.get(report)}')  # All files are downloaded
                ALL_FILES_DOWNLOADED = Python_Report.get(report)
            if report == 'reportsAmount':
                print(f'Total Number of Reports = {Python_Report.get(report)}')
                NUMBER_OF_REPORTS = Python_Report.get(report)
            if report == 'reports':
                ReportsID = str(list(dict(Python_Report['reports']).keys()))
                Full_Nest = dict(Python_Report['reports'])
                print(Full_Nest)
                print(f'Report ID = {ReportsID}')
                for NESTED_DICT in Full_Nest:
                    print(Full_Nest[NESTED_DICT]['file'])
                    CHILD_NAME = Full_Nest[NESTED_DICT]['file']['name']
                    File_Name_Nested = Summarized_File
                    print(f'File Name = {File_Name_Nested}')
                    File_HASH_Nested = Full_Nest[NESTED_DICT]['file']['hash']
                    print(f'Filed Hash = {File_HASH_Nested}')
                    File_SCAN_RESULTS = Full_Nest[NESTED_DICT]['allTags'][0]['tag']['verdict']['verdict']
                    if File_SCAN_RESULTS == 'INFORMATIONAL':
                        print('File Results == Clean')
                    else:
                        print(f'File Results == {File_SCAN_RESULTS}')
                    File_SCAN_Confidence = str(Full_Nest[NESTED_DICT]['allTags'][0]['tag']['verdict']['confidence'])
                    if File_SCAN_Confidence == '1':
                        print(f'File Confidence == 100%')
                    elif File_SCAN_Confidence != '1':
                        File_SCAN_Confidence = str(File_SCAN_Confidence).partition('.')[2]
                        print(f'File Confidence == {File_SCAN_Confidence}%')
                    print('#' * 20)
                    file.writelines(f"""
                    File_Name = {File_Name_Nested}
                    Child_File = {CHILD_NAME}
                    FlowID = {FLOW_ID}'
                    Report_Finished = {ALL_FINISHED}
                    All_Files_Downloaded = {ALL_FILES_DOWNLOADED}
                    Number_Of_Reports = {NUMBER_OF_REPORTS}
                    File_Hash = {File_HASH_Nested}
                    File_Scan_Results = {File_SCAN_RESULTS}
                    File_Scan_Confidence = {File_SCAN_Confidence}
                    {'#' * 20}    
                        """)















