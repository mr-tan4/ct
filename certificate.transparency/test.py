from core.log_client import LoginClient

if __name__ == '__main__':
    log_client = LoginClient()
    entries = log_client.get_entries(0, 10)
    print(entries.__next__())