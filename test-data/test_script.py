import subprocess


def run_secrets_scanner():
    try:
        result = subprocess.run(
            ['python', 'src/main.py', 'test-data', '--format', 'console'],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print('Secrets detected!')
        else:
            print('No secrets detected.')
    except Exception as e:
        print(f'Error running secrets scanner: {e}')

if __name__ == '__main__':
    run_secrets_scanner()