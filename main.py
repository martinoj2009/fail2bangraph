#!/usr/bin/python3
import matplotlib.pyplot as plt
import csv
import re
import numpy as np
from os import listdir,path
from sys import argv,exit

__author__ = 'Martino Jones'
__version__ = 1.0


def main():

    logsPath = ''

    if len(argv) > 1:
        logsPath = argv[1]
    else:
        if path.isdir('/var/log/fail2ban'):
            logsPath = '/var/log/fail2ban'
        else:
            print('What is the path of your logs?')
            logsPath = input()

    #Make sure the path exists
    if path.isdir(logsPath) != True:
        print('Error: The path specified does not exists!')
        print(logsPath)
        exit(-1)

    #Good to go!
    print('Starting...')

    #Get the log files in the directory
    logFiles = getFiles(logsPath)
    print(logFiles)

    #Get the banned IP addresses
    logIPs = []
    for file in logFiles:
        tmpList = readLogFile(file)
        for ip in tmpList:
            logIPs.extend(ip)

    #Get the duplicate IPs
    bannedIPs = {}
    i = len(logIPs)
    for ip in logIPs:
        if ip in bannedIPs:
            bannedIPs[ip] += 1
        else:
            bannedIPs[ip] = 1

    #Write the CSV file
    writeCSV('process.csv', bannedIPs)

    y, chartLabels = readCSV('process.csv')

    #Get the graph ready
    print('labels: ')
    print(chartLabels)

    print('y: ')
    print(y)

    #Plot all the IPs
    i = 0
    for point in y:
        plt.barh(i, y[i])
        i = i + 1

    plt.title('Attacks on the server by IP')

    #This is setting the labels on the left side
    y_pos = np.arange(len(chartLabels))
    plt.yticks(y_pos, chartLabels)

    #Display the chart
    plt.show()

#This will read in files and return comma seperated list of hts and IPs
def readLogFile(file):
    ips = []
    with open(file) as f:
        content = f.readlines()
        if str(content).__contains__('Ban'):
            ips.append(re.findall( r'[0-9]+(?:\.[0-9]+){3}', str(content)))
    return ips


def getFiles(directory):
    files = []
    for file in listdir(directory):
        if file.__contains__('log'):

            #Add the / if the path doesn't already contain it for the full path
            if directory.endswith('/') != True:
                directory = directory + '/'

            files.append(directory + file)

    return files

def writeCSV(file, dict):
    with open(file, 'w') as f:  # Just use 'w' mode in 3.x
        for key, value in dict.items():
            line = key, ',' , str(value) , '\n'
            f.writelines(line)

def readCSV(file):
    with open(str(file), mode='r') as infile:
        reader = csv.reader(infile)
        values = []
        labels = []
        for rows in reader:
            k = rows[0]
            v = rows[1]
            #Only show hits bigger than 2
            if int(v) > 2:
                labels.append(k)
                values.append(int(v)*3)

        return values, labels


if __name__ == '__main__':
    main()