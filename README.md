# A Linux Authentication Log Parser

This is a simple program which reads an authentication log from a Linux file server and
parses it to detect failed logins and stores the source IP and the number of times they tried
to login in a dictionary and attempts to see if it is a brute force attack.

## Features

* **List Slicing:** Utilizes Python's built-in list slicing for a faster lookup ensuring no unnecessary overhead.
* **Future Update** Will use Python's  **re** library to make use of regular expression for a robust and cleaner deployment.

## Program Flow

The program reads the raw log from the supplied file -> parses it to search for the keyword "Failed" -> uses list slicing to extract the source IP, source port and the user attacked -> saves the information in a dictionary file -> counts the number of failed attempts by each IP -> deduces if it is a brute force attempt -> displays the verdict to the user.

## Tech Stack

* **Language:** `Python 3.12.7`

## Prerequisites

* Enure [Python](https://www.python.org/downloads/) is installed on your machine as it is essential.

## Setup & Installation

1.  **Clone this Repository:**
    ```bash
    git https://github.com/prash-cyber/log-parser.git
    cd log-parser
    ```

2.  **Run the Program:**
    Open up another terminal in the root folder and run:
    ```bash
    python3 incident_detection.py
    ```
2.1.  **Running the Program in an IDLE:**
    The easiest way to run this program will be in a code editor such as VS Code.
    Open up VS Code (or any IDLE of your choice), click on "File -> Open Folder" and select "log-parser". It should automatically include your incident_detection.py and log.txt file. Hit the "play" button on top right to run this program.