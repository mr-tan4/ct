from core.log_client import get_info
import requests
from core.configuration import *


class All_Lists(get_info):

    def parse(self, urls):
        results = []
        for url in urls:
            result = get_roots.format(url)
            results.append(result)
        return results

    def responder(self, url):
        urls = []
        response = requests.get(url)
        data = response.json()['logs']
        for value in data:
            url = value['url']
            urls.append(url)
        return urls

    def insert_data(self, table_name, data):
        sql = 'insert into {}(url) values (\'{}\');'
        for value in data:
            sql2 = sql.format(table_name, value)
            self.connect.execute(sql2)
