from multiprocessing.managers import BaseManager
import queue, time
import pandas as pd
import postgresql


###########################
# 任务管理中心              #
# 将任务分发给每个服务器处理   #
###########################


class ManagerQueue(BaseManager):
    pass


#  任务生成类
class Generator_Task(object):

    def __init__(self):
        pass

    def task_func(self, offset):
        sql = 'select * from cert_schema.cert_info_copy1 limit 2000 offset %d;' % offset
        return sql

    def result_func(self, result=None):
        if result is not None:
            print(result)


# 任务管理器

# 任务队列
task_queue = queue.Queue()

# 结果队列
result_queue = queue.Queue()

ManagerQueue.register('get_task_queue', callable=lambda: task_queue)
ManagerQueue.register('get_result_queue', callable=lambda: result_queue)
# 绑定端口5000, 设置验证码'abc':
manager = ManagerQueue(address=('0.0.0.0', 5000), authkey=b'189213')
# 启动Queue:
manager.start()
# 获得通过网络访问的Queue对象:
task = manager.get_task_queue()
result = manager.get_result_queue()
db = postgresql.open("pq://postgres:189213@localhost/ct")
length = db.prepare('select count(*) from cert_schema.cert_info_copy1;')()
print(length[0][0])
count = 0
if length[0][0] % 2000 == 0:
    count = int(length[0][0] / 2000)
else:
    count = int(length[0][0] / 2000) + 1
print(count)
for i in range(4):
    task.put(Generator_Task().task_func(i * 2000))
# 放几个任务进去:
#
# 从result队列读取结果:
print('Try get results...')

names = db.prepare(
    'select "column_name" from information_schema.columns where table_schema=\'cert_schema\' and table_name=\'cert_info_copy1\';')
columns = []
for v in names():
    columns.append(v[0])
df = pd.DataFrame(columns=columns)
frames = []
timeout = 5.00
while (True):
    try:
        r = result.get(timeout=20)
        if isinstance(r, pd.DataFrame):
            frames.append(r)
        else:
            print(r)
    except queue.Empty as e:
        break

frame = pd.concat(frames)
print(frame)
# 已经超时
# 关闭:
