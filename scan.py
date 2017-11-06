#-*- coding:utf-8 -*-
# 读取txt的ip list，用nmap扫描存储到Mysql

import re
import sys
import nmap
import time
import logging
import threading

from MysqlConnect import Mysql

class NmapScanner(object):
    def __init__(self, work_id=1):
        self.ipreg = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        # 用于存储结果
        self.info = []
        # 端口list
        self.portlist = [
            '21,23,25,26,37,53,79,81,82,83,84,85,88,89,90,110,111,113,135,139,143,161,199,389,444,445,458,465,514,541,554,587,631,800,801,808,843,873,888,902,903,981,993,995,1010,1011,1025,1026,1027,1028,1030,1031,1032,1034,1046,1080,1081,1111,1311,1443,1720,1723,1755,1801,1863,1935,2000,2001,2002,2004,2005,2006,2008,2010,2013,2049,2100,2103,2105,2107,2121,2222,2500,2525,2601,2604,3000,3030,3128,3306,3333,3372,3690,4000,4440,4443,5000,5061,5080,5200,5222,5666,6000,6001,6002,6003,6004,6005,6006,6007,6009,6082,6100,6379,6666,6699,7000,7001,7002,7004,7007,7070,7100,7200,7443,7777,7999,8000,8001,8002,8008,8009,8010,8011,8021,8022,8031,8042,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8200,8383,8443,8649,8800,8873,8888,8899,9000,9001,9002,9003,9009,9010,9040,9080,9081,9090,9091,9099,9100,9101,9102,9103,9200,9876,9900,9998,9999,10000,10001,10002,10003,10004,10009,11211,15000,20000,30000,48080,49152,49153,49154,49155,49156,49157,49158,49159,58080',
            '22,80,443,3389,53,123,161,111,101',
            '1-20,24,27-36,38-52,54-78,86-87,91-109,112,114-134,136-138,140-142,144-160,162-198,200-388,390-442,446-457,459-464,466-513,515-540,542-553,555-586,588-630,632-799,802-807,809-842,844-872,874-887,889-901,904-980,982-992,994,996-999',
            '1000-1009,1012-1024,1029,1033,1035-1045,1047-1079,1082-1110,1112-1310,1312-1442,1444-1719,1721-1722,1724-1754,1756-1800,1802-1862,1864-1934,1936-1999',
            '2003,2007,2009,2011-2012,2014-2048,2050-2099,2101-2102,2104,2106,2108-2120,2122-2221,2223-2499,2501-2524,2526-2600,2602-2603,2605-2999',
            '3001-3029,3031-3127,3129-3305,3307-3332,3334-3371,3373-3388,3390-3689,3691-3999',
            '4001-4439,4441-4442,4444-4999',
            '5001-5060,5062-5079,5081-5199,5201-5221,5223-5665,5667-5999',
            '6008,6010-6081,6083-6099,6101-6378,6380-6665,6667-6698,6700-6999',
            '7003,7005-7006,7008-7069,7071-7099,7101-7199,7201-7442,7444-7776,7778-7998',
            '8003-8007,8012-8020,8023-8030,8032-8041,8043-8079,8091-8092,8094-8098,8101-8179,8182-8199,8201-8382,8384-8442,8444-8648,8650-8799,8801-8872,8874-8887,8889-8898,8900-8999',
            '9004-9008,9011-9039,9041-9079,9082-9089,9092-9098,9104-9199,9201-9875,9877-9899,9901-9997',
            '10005-10008,10010-11210,11212-14999,15001-19999',
            '20001-29999',
            '30001-39999',
            '40000-48079,48081-49151,49160-49999',
            '50000-58079,58081-59999',
            '60000-65535',
        ]
        # 进程数量
        self.thread_num = []

    def scan(self, ip):
        """
        多线程扫描
        """
        start_time = int(time.time())
        try:
            for num, port in enumerate(self.portlist):
                t = threading.Thread(target=self.main, args=(ip, port,))
                t.setDaemon(True)
                t.start()
                time.sleep(0.04)
                self.thread_num.append(t)

            for x in self.thread_num:
                x.join()
        except Exception, e:
            pass
        print(self.info)
        end_time = int(time.time())
        print(u"耗费时间：%d秒" % ((end_time - start_time)))
        logging.info("IP:%s 扫描时间：%d秒" % (ip, (end_time - start_time)))

    def main(self, ip, port="1-65355"):
        """
        扫描端口
        """
        if not self._is_ip(ip):
            try:
                nm = nmap.PortScanner()
                result = nm.scan(hosts=ip, arguments="-T4 -p%s" % (port))
                info = result["scan"][ip].get("tcp", {})
                for x in info:
                    if info[x]["state"] == "open":
                        # 增加结果
                        self.info.append({
                            "port": x,
                            "status": info[x]["state"],
                            "version": info[x]["version"],
                            "name": info[x]["name"],
                            "service": info[x]["product"]
                        })
                        # 写入 Mysql 里面
                        times = int(time.time())
                        sql = "insert into port_list(ip, port, version, name, addtime) value('%s', %s, '%s', '%s', %s)" % (
                        ip, int(x), info[x]["version"], info[x]["name"], times)
                        result = Mysql().execute(sql)
                        if not result:
                            print 2333333
                            logging.error("[Error] 端口写入数据库失败，SQL语句: %s" % (sql))

            except Exception, e:
                logging.error("Error: %s " % str(e))
        else:
            logging.debug("内网IP: {} 跳过portscan".format(ip))

    def _is_ip(self, ip):
        """
        判断是否是ip
        是不是内网IP
        """
        if len(re.findall(self.ipreg, ip)) > 0:
            ret = ip.split('.')
            if not len(ret) == 4:
                return True
            if ret[0] == '10':
                return True
            if ret[0] == '127' and ret[1] == '0':
                return True
            if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
                return True
            if ret[0] == '192' and ret[1] == '168':
                return True
            return False
        else:
            return True


    def _file_read(self, filename="./iplist.txt"):
        """
        读取ip列表
        """
        _obj = file(filename)
        try:
            content = _obj.read().replace(" ","").split("\n")
            return content
        except Exception,e:
            print("_file_read error: %s" % (str(e)))

if __name__ == '__main__':
    obj = NmapScanner()
    _ip_list = obj._file_read()
    for x in _ip_list:
        obj.scan(x)