#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Mysql 连接操作

import pymysql

class Mysql(object):

    def __init__(self):
        self.config = {
            "host": "127.0.0.1",
            "user": "root",
            "port": 3306,
            "password": "root",
            "db": "portscan",
        }

    def connect(self, config):
        """
        连接mysql
        """
        conn = pymysql.connect(**config)
        return conn

    def query(self, sql, argv=None):
        """
        sql查询操作
        """
        result = False
        conn = self.connect(self.config)
        try:
            cursor = conn.cursor()
            cursor.execute(sql, argv)
            result = cursor.fetchall()
        except Exception,e:
            conn.rollback()
            raise Exception(e)

        conn.close()
        return result

    def execute(self, sql, argv=None):
        """
        sql增删改操作
        """
        result = False
        conn = self.connect(self.config)
        try:
            cursor = conn.cursor()
            result = cursor.execute(sql, argv)
            conn.commit()
        except Exception, e:
            conn.rollback()
            raise Exception(e)

        conn.close()
        return result


if __name__ == "__main__":
    obj = Mysql()
    insert_sql = 'insert into crawl_info(target,start_date,end_date,commandline,user_agent) value("http://www.0aa.me",1505117567,1505117569,"http://www.0aa.me","Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)")'

    query_sql = 'select user()'

    print(obj.execute(insert_sql))