import paramiko
import random
import argparse
import time

BENIGN_COMMANDS = ["ls", "pwd", "whoami", "uptime", "date", "echo 'Hello, World!'", "df -h", "free -m", "cat /etc/os-release", "uname -a"]

class BenignSSHGenerator:
    def __init__(self):
        pass

    def generate_benign_ssh_traffic(self, target: str, username: str):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(target, username=username)
            number_of_commands = random.randint(1, 50)

            for i in range(number_of_commands):
                command = random.choice(BENIGN_COMMANDS)
                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode()
                print(f"Output from {target} for command '{command}':\n{output}")
                time.sleep(random.randint(1, 10))
            ssh.close()

        except Exception as e:
            print(f"Error generating benign SSH traffic: {e}")


def main():
    argparser = argparse.ArgumentParser(description="Generate benign SSH traffic.")
    argparser.add_argument("--target", type=str, default="sten-heimbrodt.de", help="Target SSH server to connect to.")
    argparser.add_argument("--username", type=str, default="sten", help="Username for SSH connection.")
    argparser.add_argument("--interval", type=int, default=5, help="Interval in seconds between generating traffic.")
    args = argparser.parse_args()
    generator = BenignSSHGenerator()
    while True:
        generator.generate_benign_ssh_traffic(args.target, args.username)
        time.sleep(args.interval)
if __name__ == "__main__":
    main()