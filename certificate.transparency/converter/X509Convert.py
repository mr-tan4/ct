import binascii

from asn1crypto import x509
import postgresql
import base64
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from core.configuration import subject
from datetime import datetime
from collections import OrderedDict


class Convert(object):

    def __init__(self):
        self.db = postgresql.open("pq://postgres:189213@localhost/ct")
        self.start = 0
        self.end = 0
        self.counts = 0
        self.length = 10000

    # 执行任务
    def run(self, data):
        self.counts = self.__split__(data)
        executor = ThreadPoolExecutor(self.counts)
        for count in range(self.counts):
            executor.submit(
                self.__parse__(data[count * self.length:(self.length * count) + self.length]))

    @property
    def __len__(self):
        return self.length

    # 将数据分割成多个任务
    def __split__(self, data):
        self.end = len(data)
        if self.end < self.length:
            self.counts = 1
            return self.counts
        if self.end % self.length != 0:
            self.counts = (self.end / self.length) + 1
        else:
            self.counts = self.end / self.length
        return int(self.counts)

    @property
    def __call__(self, *args, **kwargs):
        pass

    # 单次任务的执行方法
    def __parse__(self, data):
        if data is not None:
            if isinstance(data, list):
                for cert in data:
                    try:
                        cert_data = base64.b64decode(cert)
                    except binascii.Error as e:
                        print("can't decode data")
                        # 删除无用数据
                        print('delete from cert_schema.cert_data where cert_data =\'' + cert + '\'')
                        self.db.execute('delete from cert_schema.cert_data where cert_data =\'' + cert + '\'')
                        data.remove(cert)
                    try:
                        certificate = x509.Certificate().load(cert_data)
                    except ValueError as e:
                        print("try load tbs certificate in python")
                        try:
                            certificate = x509.TbsCertificate.load(cert_data)
                        except ValueError as e:
                            print("can't load byte[] in python!")
                            # 删除无用数据
                            sql = 'delete from cert_schema.cert_data where cert_data = \''
                            self.db.execute(sql + cert + '\'')
                            data.remove(cert)
                    subject = self.parse_certificate(certificate)
                    # 将得到的证书信息插入到数据库中
                    self.write(subject)

    def write(self, data):
        sql_value = ''
        value = ''
        sql = 'insert into cert_schema.cert_info_copy1({}) values ({});'
        for key in data.keys():
            sql_value += key + ','
            if isinstance(data.get(key), list):
                data[key] = ''.join(data.get(key))
            if isinstance(data.get(key), bytes):
                data[key] = data.get(key).decode()
            if isinstance(data.get(key), OrderedDict):
                for k, v in data.get(key).items():
                    v += v + ','
                data[key] = v
                print(data[key])
            if isinstance(data.get(key), str):
                if '\'\'' not in data.get(key):
                    if '\'' in data.get(key):
                        have_exception_value = data.get(key).replace('\'', '\'\'')
                        data[key] = have_exception_value
                else:
                    pass
            value += '\'' + str(data.get(key)) + '\','
        sql = sql.format(sql_value[:len(sql_value) - 1], value[:len(value) - 1])
        try:
            self.db.execute(sql)
            print("插入成功！")
        except Exception as e:
            print("sql %s" % sql)
            print(e)

    # 分解证书数据
    def parse_certificate(self, data):
        result = {}
        tmp = {}

        def parse_name(name, data):
            for k, v in data.items():
                if k == '0.9.2342.19200300.100.1.3':
                    tmp[name + 'DPA'] = v
                elif k == '2.5.4.13':
                    tmp[name + 'description'] = v
                elif k == '2.5.4.18':
                    tmp[name + 'postOfficeBox'] = v
                elif k == '2.5.4.51':
                    tmp[name + 'houseIdentifier'] = v
                elif k == '1.2.840.113549.1.9.2':
                    tmp[name + 'unstructuredName'] = v
                elif k == '0.9.2342.19200300.100.1.1':
                    tmp[name + 'userid'] = v
                elif k == '1.2.840.113549.1.9.8':
                    tmp[name + 'unstructuredAddress'] = v
                elif k == '2.5.4.16':
                    tmp[name + 'postalAddress'] = v
                else:
                    tmp[name + k] = v
            result.update(tmp)

        try:
            if data is not None:
                if isinstance(data, x509.Certificate):
                    subject_data = data.subject.native
                    issuer_data = data.issuer.native
                    parse_name("subject_", subject_data)
                    parse_name("issuer_", issuer_data)
                    tmp['algorithm'] = data.public_key.algorithm
                    tmp['sha1'] = base64.b64encode(data.public_key.sha1).decode()
                    tmp['sha256'] = base64.b64encode(data.public_key.sha256).decode()
                    result.update(tmp)
                    tmp['serial_number'] = data.serial_number
                    if data['tbs_certificate']['validity']['not_before'].native != None and \
                            data['tbs_certificate']['validity']['not_after'].native != None:
                        tmp['not_before'] = data['tbs_certificate']['validity']['not_before'].native
                        tmp['not_after'] = data['tbs_certificate']['validity']['not_after'].native
                    else:
                        tmp['not_before'] = datetime.now().strftime('%y-%m-%d %H:%M:%S')
                        tmp['not_after'] = datetime.now().strftime('%y-%m-%d %H:%M:%S')
                    result.update(tmp)
                elif isinstance(data, x509.TbsCertificate):
                    subject_data = data['subject'].native
                    issuer_data = data['issuer'].native
                    parse_name("subject_", subject_data)
                    parse_name("issuer_", issuer_data)
                    tmp['algorithm'] = data['subject_public_key_info'].algorithm
                    tmp['sha1'] = base64.b64encode(data['subject_public_key_info'].sha1).decode()
                    tmp['sha256'] = base64.b64encode(data['subject_public_key_info'].sha256).decode()
                    tmp['serial_number'] = data['serial_number'].native
                    if data['validity']['not_before'].native != None and data['validity'][
                        'not_after'].native != None:
                        tmp['not_before'] = data['validity']['not_before'].native
                        tmp['not_after'] = data['validity']['not_after'].native
                    else:
                        tmp['not_before'] = datetime.now().strftime('%y-%m-%d %H:%M:%S')
                        tmp['not_after'] = datetime.now().strftime('%y-%m-%d %H:%M:%S')
                    result.update(tmp)
                else:
                    print("certificate format not support!")
            else:
                print("certificate must be not None!", data)
        except Exception as e:
            print("解析失败", e)
        subject.update(result)
        return subject


class data_Split(object):
    def __init__(self):
        self.db = postgresql.open("pq://postgres:189213@localhost/ct")
        self.counts = 0
        self.length = 100000
        self.max_counts = 8

    def run(self):
        convert = Convert()
        data = self.__get_data__()[532017:]
        print("证书信息读取成功!")
        self.counts = self.__split__()
        for count in range(self.counts):
            convert.run(data[count * self.length:(count * self.length) + self.length])

    def __get_data__(self):
        data = self.db.prepare("select * FROM cert_schema.cert_data;")

        def converter():
            df = pd.DataFrame(data(), columns=['id', 'cert_data'])
            df = df.drop_duplicates(subset=['cert_data'])
            return df['cert_data'].tolist()

        return converter()

    def __split__(self):
        if len(self.__get_data__()) % self.length != 0:
            self.counts = (len(self.__get_data__()) / self.length) + 1
        else:
            self.counts = len(self.__get_data__()) / self.lengthz
        return int(self.counts)


if __name__ == '__main__':
    data_Split = data_Split()
    data_Split.run()
