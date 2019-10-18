from multiprocessing.managers import BaseManager
import pandas as pd
import postgresql
import time, queue


class ManagerQueue(BaseManager):
    pass


ManagerQueue.register('get_task_queue')
ManagerQueue.register('get_result_queue')

# 连接到服务器，也就是运行taskmanager.py的机器:
server_addr = '127.0.0.1'
print('Connect to server %s...' % server_addr)
m = ManagerQueue(address=(server_addr, 5000), authkey=b'189213')
# 从网络连接:
m.connect()
# 获取Queue的对象:
task = m.get_task_queue()
result = m.get_result_queue()
# 从task队列取任务,并把结果写入result队列:
db = postgresql.open("pq://postgres:189213@192.168.10.125/ct")
names = db.prepare(
    'select "column_name" from information_schema.columns where table_schema=\'cert_schema\' and table_name=\'cert_info_copy1\';')
columns = []
for v in names():
    columns.append(v[0])
while (task.qsize() != 0):
    try:
        n = task.get(timeout=1)
        print('run task %s...' % n)
        data = db.prepare(n)()
        df = pd.DataFrame(data, columns=columns)
        df = df.drop_duplicates()
        df = df.reindex([df['subject_country_name'].values, df['subject_country_name'].values])
        time.sleep(10)
        result.put(df)
    except queue.Empty:
        print('task queue is empty.')
# 处理结束:
print('worker exit.')
