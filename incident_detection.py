'''
    Author: Prashant Ram
    Description: This is a simple program which reads an authentication log from a Linux file server and
                parses it to detect failed logins and stores the source IP and the number of times they tried
                to login in a dictionary. I used simple list slicing to extract the source IP, source port and
                the user they tried to hack into, without regular expression for this simple program. 

                The program now uses regex for robust pattern matching.

                Using that information, it attempts to see if it is a brute force attack.
'''
import matplotlib.pyplot as plt
from collections import defaultdict
import re

def main():
    log_location = "log.txt"
    #log_details = read_log_no_regex(log_location)

    log_details = read_log_regex(log_location)

    # display info
    view_attacker(log_details)

    # detect probable threat type
    detect_brute_force(log_details)

# displays total unique information
def view_attacker(results):
    attacker_ip = list(results.keys())
    failed_logins = list(results.values())

    plt.bar(attacker_ip, failed_logins, color='red')
    plt.xlabel("Attacker IP")
    plt.ylabel("Number of Failed Logins")
    plt.title("Failed Login Attempts by Attacker IP")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# detects brute force attempts by the number of failed logins
def detect_brute_force(results):
    for src_ip, failed_count in results.items():
        printed_result = False
        if failed_count > 3 and not printed_result:
            print(f"Possible brute force attempt by {src_ip}")
            printed_result = True

# parse the log file 
def read_log_no_regex(log_location):
    log_line = open(log_location, "r")
    results = {}
    for line in log_line:
        line = line.strip()
        list_of_line = line.split()

        if("Failed" in list_of_line):
            # get attacker's ip
            index_of_ip = list_of_line.index("from")
            src_ip = list_of_line[index_of_ip +1]
            
            # get attacker's port 
            index_of_port = list_of_line.index("port")
            src_port = list_of_line[index_of_port +1]
            
            # get user attacked
            index_of_user = list_of_line.index("from")
            user_attacked = list_of_line[index_of_user -1]

            # save this info
            if (src_ip not in results):
                results.update({src_ip: 1})
            else:
                current_count = results.get(src_ip)
                results.update({src_ip: current_count +1})

    log_line.close()
    return results

# This function uses regex for robust pattern matching
def read_log_regex(log_location):
    # Line starting with 'Failed password for ' dont capture any word even if it exists, capture the first non-space word which 
    # is the victim then the IP
    pattern = r"Failed password for (?:.* )?(\S+) from (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"
    # this automatically initializes the count to 0 for any new IP
    results = defaultdict(int)
    # let python open and close the file automatically
    with open(log_location, "r") as log_line:
        for line in log_line:
            match = re.search(pattern, line)
            if match:
                victim_user = match.group(1)
                attacker_ip = match.group(2)
                results[attacker_ip] += 1
    return results

main()