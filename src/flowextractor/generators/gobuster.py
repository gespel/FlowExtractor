import subprocess
import time

def main():
    while True:
        subprocess.run(["gobuster", "dir", "-u", "https://sten-heimbrodt.de/", "-w", "SecLists/Discovery/Web-Content/common.txt"])
        time.sleep(10)

if __name__ == "__main__":
    main()