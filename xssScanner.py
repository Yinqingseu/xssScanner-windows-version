#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#整合各子模块
from urlparse import urlparse, parse_qsl,urlunparse,urljoin
from time import clock #代码计时(语句或函数)
import urllib
import datetime
import os
import sys
reload(sys)
type = sys.getfilesystemencoding()
# type = 'utf-8'
sys.setdefaultencoding('utf-8')
import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import StaleElementReferenceException
import random
import string
from lxml import etree
import Queue
import gzip,StringIO
import urllib2
import re
import threading
#----------------------------- URLProcess --------------------------------------------

'''
URL相关处理
@author YQ
'''
class URLProcess():
    def __init__(self, url):
        self.url = url
        self.delim = 'dnyq'

    #生成用于注入检测的全部可能url：
    def generateStrPayloadURLs(self):
        payload = self.make_test_str()
        payloaded_urls = self.getPayloadedURLs(payload)
        # print "payloaded_urls:",payloaded_urls
        return payloaded_urls

    #获取全部可能的payload url
    # 输入：payload，即替换参数的字符串
    #输出全部可能的payload url，[(payload url,改变的url参数,注入的测试字符)]
    def getPayloadedURLs(self,payload):
        self.payload_url_vars(self.url,payload)
        parsed_url = urlparse(self.url)#解析URL
        # 返回url中的参数和参数值(param,paramValue)
        url_params = parse_qsl(parsed_url.query, keep_blank_values=True)
        #返回[(payloaded url,修改的参数，payload）,...]，n个参数，n+1个构造的payload url，多一个路径中插入payload
        payloaded_urls = self.make_URLs(self.url, parsed_url, url_params,payload)
        return payloaded_urls

    #构造payload url
    #输入：orig_url：原始URL，parsed_url:urlparse()处理得到的URL对象，url_params:parse_qsl处理得到的url参数对
    #输出：
    def make_URLs(self, orig_url, parsed_url, url_params,payload):
        payloaded_urls = []
        # Create 1 URL per payloaded param
        new_query_strings = self.get_single_payload_queries(url_params,payload)
        if new_query_strings:
            # Payload the parameters
            for query in new_query_strings:
                query_str = query[0]
                params = query[1]
                p = query[2]
                # scheme       #netlo         #path          #params        #query (url params) #fragment
                payloaded_url = urlunparse(
                    (parsed_url[0], parsed_url[1], parsed_url[2], parsed_url[3], query_str, parsed_url[5]))
                payloaded_url = urllib.unquote(payloaded_url)
                payloaded_urls.append([payloaded_url, params, p])
            # Payload the URL path
            payloaded_url_path = self.payload_url_path(parsed_url,payload)
            payloaded_urls.append(payloaded_url_path)
        else:
            # Payload end of URL if there's no parameters
            payloaded_end_of_url = self.payload_end_of_url(orig_url,payload)
            payloaded_urls.append(payloaded_end_of_url)
        if len(payloaded_urls) > 0:
            return payloaded_urls

    #URL路径中添加测试字符
    #输入：payload:测试字符串 parsed_url:解析过的URL、
    #输出：路径中添加字符的URL： http://example.com/page1.php?x=1&y=2 -->http://example.com/page1.php/FUZZ/?x=1&y=2
    def payload_url_path(self, parsed_url,payload):
        path = parsed_url[2]
        if path.endswith('/'):
            path = path + payload + '/'
        else:
            path = path + '/' + payload + '/'
            # scheme, netloc, path, params, query (url params), fragment
        payloaded_url = urlunparse(
            (parsed_url[0], parsed_url[1], path, parsed_url[3], parsed_url[4], parsed_url[5]))
        payloaded_url = urllib.unquote(payloaded_url)
        payloaded_data = [payloaded_url, 'URL path', payload]
        return payloaded_data

    #每个参数生成唯一
    #输出： [(payloaded params, param, payload), (payloaded params, param, payload)]
    def get_single_payload_queries(self, url_params,payload):
        new_payloaded_params = []
        changed_params = []
        modified = False
        # Create a list of lists where num of lists = len(params)
        for x in xrange(0, len(url_params)):
            single_url_params = []
            for p in url_params:
                param, value = p
                # if param has not been modified and we haven't changed a parameter for this loop
                if param not in changed_params and modified == False:
                    new_param_val = (param, payload)
                    single_url_params.append(new_param_val)
                    changed_params.append(param)
                    modified = param
                else:
                    single_url_params.append(p)
            # Add the modified, urlencoded params to the master list
            new_payloaded_params.append((urllib.urlencode(single_url_params), modified, payload))
            modified = False
        if len(new_payloaded_params) > 0:
            # [(payloaded params, payloaded param, payload), (payloaded params, payloaded param, payload)]
            return new_payloaded_params

    #构造正常检测字符：标记字符+两个随机字母
    def make_test_str(self):
        two_rand_letters = random.choice(string.lowercase) + random.choice(string.lowercase)
        delim_str = self.delim + two_rand_letters
        return delim_str

    #URL路径最后添加测试字符
    def payload_end_of_url(self, url,payload):
        if url[-1] == '/':
            payloaded_url = url+payload
        else:
            payloaded_url = url+'/'+payload

        return [payloaded_url, 'end of url', payload]

    def payload_url_vars(self, url, payload):
        ''' Payload the URL variables '''
        payloaded_urls = []
        params = self.getURLparams(url)
        modded_params = self.change_params(params, payload) #每个参数加payload
        # print "modded_params:",modded_params
        netloc, protocol, doc_domain, path = self.url_processor(url)
        if netloc and protocol and path:
            for payload in modded_params:
                for params in modded_params[payload]:
                    joinedParams = urllib.urlencode(params, doseq=1) # doseq maps the params back together
                    newURL = urllib.unquote(protocol+netloc+path+'?'+joinedParams)
                    # Prevent nonpayloaded URLs
                    # if self.test_str not in newURL:
                    #     continue
                    for p in params:
                        if payload in p[1]:
                            changed_value = p[0]
                            payloaded_urls.append((newURL, changed_value, payload))
        if len(payloaded_urls) > 0:
            return payloaded_urls

    #解析出URL参数
    #输出：[(param1,param_value1),...(paramn,param_valuen)]
    def getURLparams(self, url):
        parsedUrl = urlparse(url)
        fullParams = parsedUrl.query
        params = parse_qsl(fullParams, keep_blank_values=True) #parse_qsl()保证顺序
        return params

    #输入：params：url中的参数对：[(param1,param_value1),...(paramn,param_valuen)]
    #输出： {payload: [[(param1, payload), (param2,param2_value )], [(param1,param1_value), (param2, payload)]]}
    def change_params(self, params, payload):
        ''' Returns a list of complete parameters, each with 1 parameter changed to an XSS vector '''
        changedParams = []
        changedParam = False
        moddedParams = []
        allModdedParams = {}
        # Create a list of lists, each list will be the URL we will test
        # This preserves the order of the URL parameters and will also
        # test each parameter individually instead of all at once
        allModdedParams[payload] = []
        for x in xrange(0, len(params)):
            for p in params:
                param = p[0]
                value = p[1]
                # If a parameter has not been modified yet
                if param not in changedParams and changedParam == False:
                    changedParams.append(param)
                    p = (param, value+payload)
                    moddedParams.append(p)
                    changedParam = param
                else:
                    moddedParams.append(p)
            # Reset so we can step through again and change a diff param
            #allModdedParams[payload].append(moddedParams)
            allModdedParams[payload].append(moddedParams)
            changedParam = False
            moddedParams = []
        # Reset the list of changed params each time a new payload is attempted
        #changedParams = []
        if len(allModdedParams) > 0:
            return allModdedParams

    #获取url的各部分： domain, protocol, and netloc
    def url_processor(self, url):
        try:
            parsed_url = urlparse(url)
            # Get the path
            path = parsed_url.path
            # Get the protocol
            protocol = parsed_url.scheme+'://'
            # Get the hostname (includes subdomains)
            hostname = parsed_url.hostname
            # Get netloc (domain.com:8080)
            netloc = parsed_url.netloc
            # Get doc domain
            doc_domain = '.'.join(hostname.split('.')[-2:])
        except:
            return
        return (netloc, protocol, doc_domain, path)
#----------------------------- Crawl --------------------------------------------
'''—————————全局变量定义 BEGIN————————————————————————————'''
crawledUrl = [] #从爬虫模块获取的测试url
deadUrl = [] #存放死链
testUrl = [] #crawlUrl经URL处理模块获得的可注入URL(存在"*"标记)
safeUrl = [] #存放不可注入url
holeUrl = [] #存在漏洞的url  [url1,url2...]，去除"*"标记
staticUrl = [] #存放伪静态url
holeMethod = [] #url对应验证方法 [get,post]
holePayload = [] #url对应验证payload，[[payload1,payload2],[payload3,payload4]] 列表嵌套列表
holePayloadType = [] #payload对应请求类型 [[1,2,3],[1,2]]
injectedPayloads = {} #存放 可注入url：payloads，payloads:type
scanDatas = {} #存放扫描结果
'''
多线程爬取URL BEGIN
广度优先遍历：根据用户配置爬虫目标网站下全部可用url
入口参数：url,depth,thread
返回：爬取的全部url，列表存储
'''
#多线程爬取类，获得多线程函数参数
#入口参数：url,depth,thread. depth = 0则无需进行爬虫
#返回：爬取的url列表
class CrawlThread(threading.Thread):
    def __init__(self,url):
        threading.Thread.__init__(self)
        self.url = url
        self.linklist = ''
    # 目标url存活性判断:
    # 存活返回 True;否则返回False
    def urlStatus(self,url):
        try:
            headers = {
                'User-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                'Referer': urlparse(url).netloc,
                'Accept-encoding': 'gzip'
                }  # 加入用户代理头部，应对一些网站的反爬虫机制
            request = urllib2.Request(url, headers=headers)
            status = urllib2.urlopen(request,timeout=10).getcode()
            if status == 200:
                return True
            else:
                deadUrl.append(url)
                return False
        except:
            return False
    #判断url域名是否为当前域名
    def judgeDomain(self,testLink):
        domain = urlparse(self.url).netloc #当前域名
        if domain == urlparse(testLink).netloc:
            return True
        else:
            return False

    # 读取整个网页
    def getHtml(self, url):
        try:
            headers = {
                'User-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                'Referer': urlparse(url).netloc,
                'Accept-encoding': 'gzip'}  # 加入用户代理头部，应对一些网站的反爬虫机制
            request = urllib2.Request(url, headers=headers)  # 去除url中‘#’后的内容
            html = urllib2.urlopen(request).read()
            fEncode = urllib2.urlopen(request).info().get('Content-Encoding')
            if fEncode == 'gzip':
                html = gzip.GzipFile(fileobj=StringIO.StringIO(html), mode="r").read()
            return html
        except:
            return ''

    #判断url是否是资源型URL，无需进行爬取
    #输出：true:是资源型 false：非资源型
    def isResourceURL(self,url):
        ignore = ['jpg', 'png', 'gif', 'css', 'ico','js','doc','txt','pdf','swf']  # 要忽略的url后缀
        parsed = urlparse(url)
        url_path = (parsed.path).strip()#去除左右两侧空格
        if '.' in url_path:
            if (url_path.split('.')[1]).lower() in ignore:
                return True
        return False

    # 爬取url页面下的全部链接，多线程作用的函数
    def getLink(self,url):
        try:
            tmpLinks = []
            html = self.getHtml(url)
            #正则表达式获取网页链接：href= src= action=后面的链接
            pattern = r"(?<=href=\").+?(?=\")|(?<=href=\').+?(?=\')|(?<=src=\').+?(?=\')|(?<=src=\").+?(?=\")|(?<=action=\').+?(?=\')|(?<=action=\").+?(?=\")"
            links = re.findall(pattern,html)  # 返回一个列表
            ###获取<a>中href的值
            bad_links = {None, '', '#', ' '}  # 无用链接列表
            bad_protocol = {'javascript', 'mailto', 'tel', 'telnet'}  # 无用的头部协议，如javascript等
            right_protocol = {'http', 'https'}  # 存放正确的协议头部
            linklist = []  # 存放正常的链接
            for link in links:
                if link in bad_links or self.isResourceURL(link):  #去除无用链接
                    continue
                if ':' in link:
                    if link.split(':')[0] in right_protocol:  #绝对地址处理
                        if self.judgeDomain(link):#域名相同
                            link = link.split('#')[0] #若url中有#，去掉#后的内容
                            linklist.append(link)
                    elif link.split(':')[0] in bad_protocol:
                        continue
                else:#相对地址处理
                    link = urljoin(self.url, link).split('#')[0]  # 若url中有#，去掉#后的内容
                    if not self.isResourceURL(link):
                        linklist.append(link) #相对变绝对
            # 去除重复链接 set()函数
            linklist = list(set(linklist))
            if linklist:
                for link in linklist:
                    if self.urlStatus(link) and link not in crawledUrl: #url存活性判断，去除死链
                        # if not self.isResourceURL(link):
                        print "爬取链接：".decode('utf-8').encode(type)+link
                        tmpLinks.append(link)
                        crawledUrl.append(link)
                return tmpLinks
            else:#不再存在未爬取链接
                return []
        except:
            return []

    def run(self): #线程创建后会直接运行run函数
        self.linklist = self.getLink(self.url)

    def getDatas(self):
        return self.linklist

    #广度遍历，爬取指定深度全部url
    def crawlDepth(self,depth,maxThread):
        threadpool = [] #线程池
        crawledUrl.append(self.url)
        if depth == 0:
            return crawledUrl
        else:
            nowDepth = 1
            print "爬取深度：".decode('utf-8').encode(type), nowDepth
            th = CrawlThread(self.url)#获得深度为1时的全部url
            th.setDaemon(True)
            th.start()
            th.join()
            datas = th.getDatas()
            if datas:
                testLinks = Queue.deque(datas)
            else:#该网址不存在可爬虫链接
                return crawledUrl
            while nowDepth < depth and testLinks:
                nowDepth = nowDepth + 1
                print "爬取深度：".decode('utf-8').encode(type), nowDepth
                tmpLinks = []
                while testLinks:
                    while len(threadpool) < maxThread:
                        if testLinks:
                            t = CrawlThread(testLinks.pop())
                            t.setDaemon(True)
                            threadpool.append(t)
                            t.start()
                        else:
                            break
                    for thread in threadpool:#等待线程结束
                        thread.join()
                        #取出线程数据
                        tmp = thread.getDatas()
                        if tmp:
                            tmpLinks.extend(tmp)
                    threadpool = []
                if tmpLinks:
                    testLinks = list(set(tmpLinks))
                else:
                    testLinks = Queue.deque([])
            return crawledUrl


# 秒数转时分秒函数
def sectohms(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return "%02d:%02d:%02d" %(h, m, s)
#----------------------------- outPointJudge --------------------------------------------
'''
注入点输出位置判断类:
使用python lxml，利用xpath语法实现
输入：html源码，待查找的目标字符串
输出：输出点位置类别：
a.标签之间:
    a2:特殊标签之间:
        textarea title iframe noscript noframes xmp plaintext math
        style
    a1:普通标签之间
b.标签之中：属性之中,未区分属性与事件
    b1: 标签之内非特殊属性中：闭合属性+特殊属性+伪协议+攻击代码
    b2: 标签之内非特殊属性中：闭合属性+事件+攻击代码
    b3: 标签之内非特殊属性中且标签包含hidden属性不可编辑：闭合属性+闭合标签+a1型攻击向量
    b41: 标签之内特殊属性之中：伪协议+攻击代码
    b42: 标签之内事件之中：攻击代码
c.js代码中
一个注入点可能存在多个不同类型的输出点，
因此返回字典，包含所有可能的输出点类型及其信息，测试时需选取所有类型的攻击向量
'''

#目前实现了a1,a2,b41,b42,c的划分，b1，b2与b3合并为b123
class outPointJudge():
    def __init__(self,html,target):
        self.html = html.encode('utf-8')#unicode转字符串
        self.target = str(target) #要查找的目标字符,int转str
        self.se = etree.HTML(self.html)
        self.type = {} #存储输出点信息：输出点位置类别:对应内容
        self.sp_attr = ['src','href'] #特殊属性

    def run(self):
        self.get_point_type()
        return self.type #字典：{位置类型:[标签名]|[属性名]} eg:{'a1': ['textarea'], 'c': ['script'], 'a2': ['div'], 'b': ['src', 'href', 'onclick']}

    #输出点位置判断，可能存在多个输出点，存储输出点位置类型及其相关信息，字典格式
    def get_point_type(self):
        # 标签之间判断：a1,a2,c,d1备选
        out_eles = self.txt_contains_target()
        # print 'out_eles个数：',len(out_eles)
        tag_contain_target = []  # 存储标签内容包含目标字符的标签
        special_tags = ['textarea', 'title', 'iframe', 'noscript',
                        'noframes', 'xmp', 'plaintext', 'math', 'style']  # 特殊标签
        if out_eles:
            for e in out_eles:
                # 判断目标字符所在标签类型
                # print e.tag,"标签内容：",e.text
                tag_contain_target.append(e.tag)
                if e.tag in special_tags:  # 特殊标签之间
                    if 'a2' not in self.type.keys():
                        self.type['a2'] = list() #存储对应的标签名
                        self.type['a2'].append(e.tag)
                    elif e.tag not in self.type['a2']:
                        self.type['a2'].append(e.tag)
                elif e.tag == 'script' and 'c' not in self.type.keys():  # js代码中
                    self.type['c'] = list()
                    self.type['c'].append(e.tag)
                else:  # 普通标签之间
                    if 'a1' not in self.type.keys():
                        self.type['a1'] = list()
                        self.type['a1'].append(e.tag)
                    elif e.tag not in self.type['a1']:
                        self.type['a1'].append(e.tag)
            tag_contain_target = list(set(tag_contain_target))
            # print '标签内容包含目标字符的标签：', tag_contain_target
        #标签之内判断
        in_eles = self.attr_contains_target() #获取属性包含目标字符串的元素
        attr_contian_target = [] #存储属性值包含目标字符的属性名
        if in_eles:
            # if 'b' not in self.type.keys():
            #     self.type['b'] = list()
            for i in in_eles:
                attr_dict = i.attrib #获取元素属性,字典{属性：属性值}
                attr_contian_target.extend(self.get_attr_contain_target(attr_dict))
            attr_contian_target = list(set(attr_contian_target)) #去重
            for attr in attr_contian_target:
                if 'on' in attr: #事件之中
                    if 'b42' not in self.type.keys():
                        self.type['b42'] = []
                    if attr not in self.type['b42']:
                        self.type['b42'].append(attr)
                elif attr in self.sp_attr: #特殊属性之中
                    if 'b41' not in self.type.keys():
                        self.type['b41'] = []
                    if attr not in self.type['b41']:
                        self.type['b41'].append(attr)
                else: #非特殊属性中
                    if 'b123' not in self.type.keys():
                        self.type['b123'] = []
                    if attr not in self.type['b123']:
                        self.type['b123'].append(attr)
            # self.type['b'].extend(attr_contian_target)
            # print '包含目标字符的属性：',attr_contian_target


    #字典key:value处理，输出value(属性值)中包含指定字符的key(属性)
    #输入：页面元素的属性字典
    #输出：列表，包含指定字符的属性名[属性1，属性2,...]
    def get_attr_contain_target(self,attr_dic):
        attrs = []
        for key,value in attr_dic.items():
            if value.find(self.target) != -1:
                attrs.append(key)
        return  attrs

    #选出包含目标字符的元素：即包含目标字符的那行
    #返回列表：包含目标字符的元素[line1,line2..]
    def contain_target(self,li):
        contain_line = []
        for l in li:
            if l.find(self.target) != -1:
                contain_line.append(l)
        return contain_line


    #查找属性值包含目标字符的页面元素
    #返回找到的页面元素elements,列表
    def attr_contains_target(self):
        xpath = "//*[contains(@*,\'"+self.target+"\')]" #单引号不可少
        elems = self.se.xpath(xpath)
        return elems

    #查找标签内容包含目标字符的页面元素
    #返回找到的页面元素elements，列表
    def txt_contains_target(self):
        xpath = "//*[contains(text(),\'"+self.target+"\')]"
        elems = self.se.xpath(xpath)
        #br标签分割的文本:无法直接被text()获取
        br_xpath = "//*[contains(text()[preceding-sibling::br],\'"+self.target+"\')]"
        elems.extend(self.se.xpath(br_xpath))
        return elems
#----------------------------- payload vector   --------------------------------------------
'''
初始攻击向量数据结构
'''
class vector():
    def __init__(self,value=''):
        self.value = value #具体攻击向量
        self.r_pre = ''  # 闭合前缀
        self.r_suf = ''  # 闭合后缀
        self.tag = ''  #标签名
        self.attr = '' #属性名
        self.attr_value = '' #属性值
        self.event = '' #事件名
        self.event_value = '' #事件值
        self.content = '' #标签之间的内容
        self.type = '' #攻击向量类别
        self.seperator = ' ' #默认连接符为空格
        # self.pattern = []
        self.trigger = '0' #攻击向量触发方式：默认0：自动触发，1：点击后触发

'''
变异后的攻击向量数据结构
'''

class finalVector():
    def __init__(self, value, type, rule=[]):
        self.value = value  # 变异后的攻击向量字符串
        self.type = type  # 攻击向量类别
        self.rule = rule  # 采用的变异规则
        self.order = len(rule)  # 变异阶次：采用的变异规则数量
        self.trigger = '0'  # 攻击向量触发方式，0：自动触发 1：点击后触发
#-------------------------------------------------

#----------------------------- databaseOperation --------------------------------------------
#将攻击向量存储至数据库表中
#连接至Mysql数据库并创建游标，返回游标
import mysql.connector
#数据库相关操作类：存储初始攻击向量，变异攻击向量
class databaseOperation():
    def __init__(self):
        self.conn = mysql.connector.connect(user='xssScaner_user',password='yinqing1',host='localhost',database='xsspayloads')
        self.cur = self.conn.cursor()
        self.conn.commit()

    #查询数据表获取各类型变异XSS攻击向量
    #输入：type:攻击向量类型
    #输出对应类型的攻击向量对象，列表形式
    def getVectors(self,type):
        self.cur.execute("SELECT * FROM mutated_xss_payloads where trigger_method = '0' and payload_type='"+type+"' ")
        rows = self.cur.fetchall()
        vectors = []
        for r in rows:
            v = finalVector(value=r[2],type=r[1])
            v.trigger = r[3]
            v.rule = []
            v.rule.append(r[4])
            vectors.append(v)
        return vectors

    #查询数据表获取给类型初始XSS攻击向量
    #输入：type:攻击向量类型
    #输出：对应类别的XSS攻击向量对象，列表形式
    def getInitialVectors(self,type):
        self.cur.execute("SELECT * FROM initial_xss_payloads where trigger_method = '0' and payload_type='" + type + "'")
        rows = self.cur.fetchall()
        vectors = []
        for r in rows:
            v = vector(value=r[2])
            v.type = r[1]
            v.trigger = r[3]
            vectors.append(v)
        return vectors
'''
各类型XSS攻击向量获取
'''
d = databaseOperation()
#初始XSS攻击向量获取
a1_initialVectors = d.getInitialVectors('a1') #a1型finalVector对象列表
b1_initialVectors = d.getInitialVectors('b1') #b1型finalVector对象列表
b2_initialVectors = d.getInitialVectors('b2') #b2型finalVector对象列表
b3_initialVectors = d.getInitialVectors('b3') #b3型finalVector对象列表
b41_initialVectors= d.getInitialVectors('b41') #b41型finalVector对象列表
b42_initialVectors = d.getInitialVectors('b42') #b42型finalVector对象列表
c_initialVectors= d.getInitialVectors('c') #c型finalVector对象列表
#变异XSS攻击向量
a1_finalVectors = d.getVectors('a1') #a1型finalVector对象列表
b1_finalVectors = d.getVectors('b1') #b1型finalVector对象列表
b2_finalVectors = d.getVectors('b2') #b2型finalVector对象列表
b3_finalVectors = d.getVectors('b3') #b3型finalVector对象列表
b41_finalVectors = d.getVectors('b41') #b41型finalVector对象列表
b42_finalVectors = d.getVectors('b42') #b42型finalVector对象列表
c_finalVectors = d.getVectors('c') #c型finalVector对象列表
#-------------------------------- generateMutatePayloads -----------------------------
#一维变异攻击向量生成：依次读取初始攻击向量，运用各变异规则，生成变异的XSS攻击向量，存储到数据中
import copy
class finalVectorsGenerate():
    def __init__(self):
        # 存储最终的各类别攻击向量对象
        self.a1_final_vectors = []  # 无需闭合
        self.b1_final_vectors = []  # 闭合属性+特殊属性+js
        self.b2_final_vectors = []  # 闭合属性+事件
        self.b3_final_vectors = []  # 闭合属性+闭合标签+a1
        self.b41_final_vectors = []  # 特殊属性中
        self.b42_final_vectors = []  # 事件中
        self.c_final_vectors = []  # js中

    # 输入：要闭合的特殊标签名，如textarea
    # 输出：a2型变异XSS攻击向量列表：闭合标签+a1型攻击向量
    def a2FinalVectorsGenerate(self, sp_tag):
        a2_final_vectors = []
        self.a1FinalVectorsGenerate()
        for vec in self.a1_final_vectors:
            v = copy.deepcopy(vec)
            v.value = "</" + sp_tag + ">" + v.value + "<" + sp_tag + ">"
            v.type = 'a2'
            a2_final_vectors.append(v)
        return a2_final_vectors
#-------------------------------- xssScan.py -----------------------------------------
'''
XSS检测模块：继承URLProcess类，实现对URL的处理，实现URL XSS
输入要检测的URL页面，对该页面进行检测，检测完毕，关闭该页面
@author YQ
'''
class XSSDec(URLProcess,outPointJudge):
    def __init__(self,url):
        URLProcess.__init__(self,url)
        self.url = url #当前检测页面URL
        self.driver = self.getDriver()
        # self.driver =  webdriver.Firefox()
        self.handle = self.driver.current_window_handle #初始窗口句柄
        self.results = [] #存储XSS漏洞信息(漏洞所在URL，注入点位置，检测成功的攻击向量)
        self.flag = '17929'  #弹窗字符串，正常注入字符串,使用数字更安全
        self.alert = 0  # 记录页面初始弹窗数
        self.trigger_index = ''#触发点index，若为空，不存在可点击触发点，则在input元素上回车。
        self.request = 0 #记录发送的http请求数量
        self.crawled = [] #存储处理该URL过程中应点击按钮，新产生的URL
        self.faied_url = [] #存储响应超时的链接

    # 配置firefox,禁止加载图片,禁用样式表文件
    def getDriver(self):
        options = Options()
        options.add_argument('-headless')
        firefox_profile = webdriver.FirefoxProfile()
        firefox_profile.set_preference("permissions.default.stylesheet", 2)  # 禁用样式表文件 1为允许加载
        firefox_profile.set_preference("permissions.default.image", 2)  # 不加载图片
        firefox_profile.set_preference("dom.ipc.plugins.enabled.libflashplayer.so", 2)  # 关flash
        firefox_profile.update_preferences()  # 更新设置
        return webdriver.Firefox(firefox_profile, timeout=10, firefox_options=options)

    #获取页面可点击元素
    #输出：可点击元素列表
    def getClickableEle(self):
        pass

    #点击页面可点击元素，获取新链接
    #可点击元素列表
    def clickAllClickableEle(self,eles):
        pass

    #XSS检测运行函数
    def start(self):
        try:
            self.driver.implicitly_wait(5)  # 隐式等待时间8秒，找不到元素将等待8秒
            self.driver.set_page_load_timeout(10)  # 设置页面加载超时时间
            self.driver.get(self.url)
        except:
            self.faied_url.append(self.url)
            return []
        else:
            try:
                # 滚动至页面底端
                self.scroll()
                # 清除初始页面弹窗
                while self.alert_is_present():
                    alert = self.alert_is_present()
                    alert.dismiss()  # 清除弹窗
                    self.alert = self.alert + 1
                # print '页面初始弹窗数：'.decode('utf-8').encode(type), self.alert
                self.driver.switch_to.default_content()
                # url xss
                self.url_xss()
                #form xss
                self.form_xss()
                # 显示检测结果
                self.getResults()
                print "URL:".decode('utf-8').encode(type), self.url, "检测结束。".decode('utf-8').encode(type)
                return self.results
            except Exception as e:
                # print e
                return []
                pass

    #检测结束，退出驱动
    def quit(self):
        try:
            self.driver.quit()  # 退出驱动，关闭全部窗口
        except Exception as e:
            # print e
            pass
    # 滚动至页面底端,获取完整html源码
    def scroll(self):
        self.driver.execute_script("""
            (function () {
                var y = document.body.scrollTop;
                var step = 100;
                window.scroll(0, y);
                function f() {
                    if (y < document.body.scrollHeight) {
                        y += step;
                        window.scroll(0, y);
                        setTimeout(f, 50);
                    }
                    else {
                        window.scroll(0, y);
                        document.title += "scroll-done";
                    }
                }
                setTimeout(f, 1000);
            })();
            """)
        time.sleep(3)  # 等待页面缓冲，不可少

    # 探子请求：发送唯一的随机字符,长度30（最短攻击向量长度）---长度限制的注入点无需注入
    def make_unique_flag(self,size=30, chars=string.ascii_lowercase+ string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    # 清除掉页面初始弹窗
    def accept_initial_alert(self, num):
        try:
            if num != 0:
                # print "需清除页面初始弹窗%d个"%(num)
                while num:
                    alert = self.driver.switch_to.alert  # 切换至弹窗
                    alert.dismiss()
                    num = num - 1
                self.driver.switch_to.default_content()
            else:
                return
        except Exception:  # 不存在弹窗就是报错
            return
    # 判断页面是否弹窗
    # 输出：False:无弹窗 ；弹窗成功返回alert对象
    def alert_is_present(self):
        time.sleep(1)  # 确保DOM更新,不可少，否则会报错
        try:
            # 判断是否弹窗
            alert = self.driver.switch_to.alert  # 切换至弹窗
            text = alert.text  # 试图获取弹窗内容
            # 可获取内容，即不产生异常，则有XSS，截屏保存
            return  alert
        except Exception:  # 不存在弹窗就是报错
            # Means that XSS is NOT present
            return False

    #根据输出点类别生成待测攻击向量
    #输入：输出点类型字典 键：值=输出点类型：[对应类型信息]
    #输出：全部输出点对应类型的攻击向量对象列表
    def getallTypeVectors(self,out_point_dict):
        vectors = []
        out_point_types = out_point_dict.keys() #一个注入点可能存在多个类型的输出点
        for t in out_point_types:
            if t == 'a1':
                vectors.extend(a1_finalVectors)
            elif t == 'a2':
                sp_tags = out_point_dict[t] #要闭合的特殊标签名列表
                #生成a2型攻击向量=闭合标签+a1型攻击向量
                a2_final_vectors = []
                for sp_tag in sp_tags:
                    a2_final_vectors.extend(finalVectorsGenerate().a2FinalVectorsGenerate(sp_tag))
                vectors.extend(a2_final_vectors)
            elif t == 'b41':
                vectors.extend(b41_finalVectors)
            elif t == 'b42':
                vectors.extend(b42_finalVectors)
            elif t == 'b123':
                vectors.extend(b1_finalVectors)
                vectors.extend(b2_finalVectors)
                vectors.extend(b3_finalVectors)
            elif t == 'c':
                vectors.extend(c_finalVectors)
        return vectors
    #======================================= URL XSS  ======================================
    #扫描URL，判断是否可XSS
    def url_xss(self):
        print "开始URL XSS检测".decode('utf-8').encode(type)
        inject_payload_urls = self.isURLInjectable() #该URL的可注入payload url:[(payload url,param,payload,out point(注入输出位置待定))]
        for inject_payload_url in inject_payload_urls:
            payload_url = inject_payload_url[0] #payload构造的url
            inject_param = inject_payload_url[1] #注入参数
            str_payload = inject_payload_url[2]  #检测字符串
            out_point_dict = inject_payload_url[3] #输出点信息，字典，键：值=输出点类型：[类型信息]
           #根据输出点类型选取攻击向量对象集 finalVector对象
            vectors = self.getallTypeVectors(out_point_dict)
            print "url xss 待检测XSS数量：".decode('utf-8').encode(type),len(vectors)
            # 攻击向量填充可注入URL
            for v in vectors:
                vector_value = v.value #具体的攻击向量字符串
                attack_url = payload_url.replace(str_payload,vector_value) #将注入字符替换为攻击向量
                #发送xss url，判断是否存在漏洞
                self.driver.get(attack_url)
                self.request = self.request + 1 #http请求数+1
                self.accept_initial_alert(self.alert) #清除初始弹窗
                if self.alert_is_present():#判断页面是否有弹窗
                    alert = self.alert_is_present()
                    content = alert.text
                    text = content.encode("utf-8") #unicode转str
                    # print "text:",text,"type:",type(text)
                    alert.accept()
                    while self.alert_is_present():  # 清除存在多个输出点导致的多个弹窗
                        alert = self.alert_is_present()
                        alert.accept()
                    self.driver.switch_to.window(self.handle)
                    if text == self.flag:#xss成功，保存漏洞信息
                                             #初始URL 注入类型  攻击向量 注入点
                        self.results.append((self.url,'url',  vector_value, inject_param))
                        self.driver.close() #关闭当前窗口
                        break

    # URL可注入判断：是否含参，所含参数是否在页面有输出点
    # 输出：列表：可注入URL的信息：[[payload url,inject param,payload,[out_point1,out_point2...]],]  ； False不可注入
    def isURLInjectable(self):
        # 判断是否含参
        url_params = self.getURLparams(self.url)
        injectable_urls = []  # 存放注入的payload url
        if url_params:
            #可注入判断
            str_payloaed_urls = self.generateStrPayloadURLs()#正常字符注入各参数形成的url
            for str_payloaed_url in str_payloaed_urls:
                payloaded_url = str_payloaed_url[0] #payload构造的url
                param = str_payloaed_url[1] #注入参数
                str_payload = str_payloaed_url[2] #检测字符串
                #请求构造的url，查找是否有输出
                html = self.getPageHtml(payloaded_url)
                if html.find(str_payload) == -1:#未找到
                    continue
                else:#找到
                    #确定输出位置
                    out_point_type = outPointJudge(html,str_payload).run() #字典类型，键为位置类型，值为输出点信息
                    str_payloaed_url.append(out_point_type) #可注入URL信息扩展输出点类型
                    injectable_urls.append(str_payloaed_url)
        # print "可注入URL信息：".decode('utf-8').encode(type),injectable_urls
        return injectable_urls

    #获取URL源码
    def getPageHtml(self,url):
        try:
            self.driver.get(url)
            self.request = self.request + 1  # http请求数+1
            return self.driver.page_source
        except Exception as e:
            # print e
            return ''
            pass
    # ======================================= URL XSS  ======================================
    # ======================================= FORM XSS ======================================
    #检测页面form表单中的xss
    def form_xss(self):
        self.window_xss_form()
        self.iframe_xss_form()
    #触发点触发后页面情形判断,根据不同页面情形，进行处理
    #输出：0：未产生新页面；1：新页面覆盖原页面 2：打开新页面
    def pageStatus(self):
        handles = self.driver.window_handles
        current_url = self.driver.current_url #当前URL
        if current_url == self.url: #driver的URL未改变
            if len(handles) == 2: #打开新页面
                return 2
            else:
                return 0
        else:
            return 1 #新页面覆盖原页面

    #获取页面中form元素
    #返回form元素列表forms = [form1,...,form]
    def getFormEles(self):
        try:
            #当前源码中的form：window 或 iframe
            forms = self.driver.find_elements_by_tag_name('form')
            if forms:
                return forms
            else:
                return []
        except:
            return []

    #获取form中的input元素
    def getinputsInForm(self,form):
        return form.find_elements_by_tag_name('input')
    #获取form中的textarea元素
    def gettextareasInForm(self,form):
        return form.find_elements_by_tag_name('textarea')
    #获取form中的button元素
    def getbuttonsInForm(self,form):
        return form.find_elements_by_tag_name('button')

    # 处理form表单，找到form表单的注入点和触发点
    # 输入：form:form元素
    # 输出：列表，[注入点，触发点] eg:[[(input1,input)],[触发点：submit]]
    def parse_form(self,form):
        #获取form表单中的可注入子节点
        input_active = ['submit','button','reset'] #交互点input的type类型
        results = [] #存储处理结果
        injects = []  # 存储注入点
        submit = []  # 存储触发点
        inputs = self.getinputsInForm(form)
        textarea = self.gettextareasInForm(form)
        buttons = self.getbuttonsInForm(form)
        if inputs:
            for i in inputs:
                input_type = i.get_attribute('type')
                if input_type == 'hidden':#不可编辑判断
                    continue
                elif input_type in input_active: #注入点判断
                    submit.append(i)
                #包含onclick属性的input?
                else:
                    injects.append(i) #存储注入点
        if textarea:
            for t in textarea:
                injects.append(t)
        if buttons:
            for b in buttons:
                if b.isEnabled():
                    submit.append(b)
        results.append(injects)
        results.append(submit)
        return results

    # 判断页面是否更新
    # 输入：elem:原页面元素，若已更新则找不到该元素而产生异常
    # 输出：TRUE:已更新 FALSE:未更新
    def isDOMRefresh(self, elem):
        try:
            tag_name = elem.tag_name
            return False  # 未更新
        except StaleElementReferenceException:
            return True  # 已更新

    #获取注入点中的标签名为input的元素
    #输入：injects:注入点元素列表
    #输出：input标签名的注入点
    def inputInjects(self,injects):
        for i in injects:
            if i.tag_name == 'input':
                return i
        return None

    #触发触发点，提交表单：回车 or 点击触发点
    #输入：submits:触发点列表 injects:注入点列表
    #输出：页面状态:触发点触发成功，页面刷新，；-1:触发点均无效
    def submitForm(self,submits,injects):
        if len(submits) == 0:#触发点为0个，则在input元素上回车
            input_inject = self.inputInjects(injects)
            input_inject.send_keys(Keys.ENTER)
            page_status = self.pageStatus()
            self.accept_initial_alert(self.alert)  # 清除初始页面弹窗
            if page_status  == 0 and not self.isDOMRefresh(submits[0]):
                return -1
            self.request = self.request + 1  # http请求数+1
            return page_status
        else:
            for s in xrange(len(submits)):
                submits[s].click()
                time.sleep(2)
                self.accept_initial_alert(self.alert)
                #点击之后页面没反应
                page_status = self.pageStatus()
                if  page_status == 0 and not self.isDOMRefresh(submits[0]):
                    continue
                else:
                    self.request = self.request + 1  # http请求数+1
                    self.trigger_index = s
                    return page_status
            return -1

    #提交表单，根据页面状态，判断页面是否产生弹窗
    #输入：submits:触发点列表 injects:注入点列表，page_status：页面状态
    #输出：True：页面产生弹窗 False：页面不产生弹窗
    def submitandJudege(self,submits,injects,page_status):
        if self.trigger_index  == '':  # 可点击触发点为0 ，则在input元素上回车
            input_inject = self.inputInjects(injects)
            input_inject.send_keys(Keys.ENTER)
            self.request = self.request + 1  # http请求数+1
            self.accept_initial_alert(self.alert)  # 清除初始页面弹窗
        else:
            submits[self.trigger_index].click() #点击触发点
            self.request = self.request + 1  # http请求数+1
            self.accept_initial_alert(self.alert)
        time.sleep(2)
        #根据页面状态，进行弹窗判断
        if page_status == 2:  # 打开新页面，应到新页面查找
            handles = self.driver.window_handles
            handle = handles[-1]  # 获取最新的句柄
            self.driver.switch_to.window(handle)  # 切向新打开的页面
            # 监测页面弹窗
            if self.alert_is_present():
                alert = self.alert_is_present()
                # 获取弹窗内容，判断是否与预期一致
                content = alert.text
                content = content.encode('utf-8')
                # print '弹窗内容：'.decode('utf-8').encode(type), content
                while self.alert_is_present():  # 清除存在多个输出点导致的多个弹窗
                    alert = self.alert_is_present()
                    alert.accept()
                self.driver.close()  # 关闭新打开的页面
                self.driver.switch_to.window(self.handle)  # 切回原检测页面
                if content == self.flag:  # 弹窗内容符合预期
                    return True
            else:  # 无弹窗
                self.driver.close()  # 关闭新打开的页面
                self.driver.switch_to.window(self.handle)  # 切回原检测页面
                return False
        elif page_status == 1:  # 新页面覆盖原页面
            # 监测页面弹窗
            if self.alert_is_present():
                alert = self.alert_is_present()
                # 获取弹窗内容，判断是否与预期一致
                content = alert.text
                content = content.encode('utf-8')
                # print '弹窗内容：'.decode('utf-8').encode(type), content
                while self.alert_is_present():  # 清除存在多个输出点导致的多个弹窗
                    alert = self.alert_is_present()
                    alert.accept()
                self.driver.back()
                self.accept_initial_alert(self.alert)  # 清除初始弹窗
                if content == self.flag:  # 弹窗内容符合预期
                    return True
            else:  # 无弹窗
                self.driver.back()  # 存在连续两次后退的情况
                self.accept_initial_alert(self.alert)  # 清除初始弹窗
                return False
        else:  # URL不变更
            # 监测页面弹窗
            if self.alert_is_present():
                alert = self.alert_is_present()
                # 获取弹窗内容，判断是否与预期一致
                content = alert.text
                content = content.encode('utf-8')
                # print '弹窗内容：'.decode('utf-8').encode(type), content
                while self.alert_is_present():  # 清除存在多个输出点导致的多个弹窗
                    alert = self.alert_is_present()
                    alert.accept()
                if content == self.flag:  # 弹窗内容符合预期
                    return True
            return False
        return False

    # 表单中的注入点可注入判断：提交探子字符是否在本页面，不在本页面的无法处理
    # 输入：inject_index:页面form列表对应form的序号 form_index：form表单对应序号
    # 输出：(页面状态:0,1,2，注入点是否可注入：true/False，输出点类型)
    def isInputInjectable(self, inject_index, form_index):
        forms = self.getFormEles()
        form = forms[form_index]
        print '开始可注入判断'.decode('utf-8').encode(type)
        # 注入点、触发点获取
        [injects, submit] = self.parse_form(form)
        flag = self.make_unique_flag()
        print '注入点%d, %s'.decode('utf-8').encode(type) % (inject_index, injects[inject_index].get_attribute('outerHTML').decode('utf-8').encode(type)), ' 可注入判断'.decode('utf-8').encode(type)
        injects[inject_index].clear()  # 注入点,清空输入
        injects[inject_index].send_keys(flag)
        # 非注入点填入普通字符串
        test_str = self.make_unique_flag(6)
        for j in xrange(len(injects)):#其它注入点注入相同的字符，防止出现类似要密码一致的form表单
            if j != inject_index:
                injects[j].clear()
                injects[j].send_keys(test_str)
        # 表单提交，点击触发点
        page_status = self.submitForm(submit,injects)
        self.accept_initial_alert(self.alert)
        if page_status == -1:#表单不可提交
            return (0, False, [])
        else:#表单提交成功
            # 获取页面状态，根据页面状态，切换driver，寻找是否存在输出点
            if page_status == 2:  # 打开新页面，应到新页面查找
                # print "注入触发页面状态：打开新页面".decode('utf-8').encode(type)
                handles = self.driver.window_handles
                handle = handles[-1]  # 获取最新的句柄
                self.driver.switch_to.window(handle)  # 切向新打开的页面
                # 判断页面是否包含探子字符
                html = self.driver.page_source
                if html.find(flag) != -1:
                    # 获取输出点位置信息
                    out_point_dict = outPointJudge(html, flag).run()  # 字典
                    self.driver.close()  # 关闭新打开的页面
                    self.driver.switch_to.window(self.handle)  # 切回原检测页面
                    return (2, True, out_point_dict)  # 返回输出位置类型
                else:
                    self.driver.close()  # 关闭新打开的页面
                    self.driver.switch_to.window(self.handle)  # 切回原检测页面
                    return (2, False)
            elif page_status == 1:  # 新页面覆盖原页面
                # print "注入触发页面状态：新页面覆盖原页面".decode('utf-8').encode(type)
                # 判断页面是否包含探子字符
                html = self.driver.page_source
                if html.find(flag) != -1:
                    # 获取输出点位置信息
                    out_point_dict = outPointJudge(html, flag).run()  # 字典
                    self.driver.back()  # 存在连续两次后退的情况
                    self.accept_initial_alert(self.alert)  # 清除初始弹窗
                    return (1, True, out_point_dict)  # 返回输出位置类型
                else:
                    self.driver.back()  # 存在连续两次后退的情况
                    self.accept_initial_alert(self.alert)  # 清除初始弹窗
                    return (1, False, [])
            else:  # URL不变更
                # print "注入触发页面状态：未产生新页面".decode('utf-8').encode(type)
                #页面更新
                if self.isDOMRefresh(injects[inject_index]):
                    # 判断页面是否包含探子字符
                    html = self.driver.page_source
                    if html.find(flag) != -1:
                        # 获取输出点位置信息
                        out_point_dict = outPointJudge(html, flag).run()  # 字典
                        return (0, True, out_point_dict)  # 返回输出位置类型，待定
                return (0,False,[])


    #根据页面状态，切换driver,获取最新的正在处理的form元素
    #输入：index为处理的form元素标号 page_status;2:打开新页面 1:新页面覆盖原页面 0:URL不变更
    #输出：页面对应index的form元素
    def getLatestForm(self,index,page_status):
        if page_status == 2:
            self.driver.switch_to.window(self.handle) #应切回原始页面
        elif page_status == 1:
            while self.alert_is_present():
                alert = self.alert_is_present()
                alert.dismiss()
            self.driver.get(self.url)  # 存在连续两次后退的情况
            self.accept_initial_alert(self.alert)  # 清除初始弹窗
        forms = self.getFormEles()
        return forms[index]

    #页面form注入点XSS检测
    def window_xss_form(self):
        print 'window_xss_form 检测开始！'.decode('utf-8').encode(type)
        #window中form xss检测
        try:
            forms = self.getFormEles()
            print '页面存在%d个form表单'.decode('utf-8').encode(type)%(len(forms))
            num_of_form = len(forms)
            #检测页面每个form
            for index  in xrange(num_of_form):
                #获取表单注入点
                f = self.getLatestForm(index, self.pageStatus())
                [injects, submit] = self.parse_form(f)
                # 依次遍历每个注入点
                for iji in xrange(len(injects)):
                    #页面状态，是否可注入，输出点类型
                    (page_status,ii,out_point_dict)= self.isInputInjectable(iji,index)
                    self.accept_initial_alert(self.alert)
                    if ii:
                        print '注入点可注入!'.decode('utf-8').encode(type)
                        print "输出点类型：".decode('utf-8').encode(type),out_point_dict
                        # 遍历向量集
                        vectors = self.getallTypeVectors(out_point_dict)# 根据输出点类型选取攻击向量对象集 finalVector对象
                        print "待测攻击向量个数：".decode('utf-8').encode(type),len(vectors)
                        d = 0
                        # vectors =  ["<script>alert(17929)</script>","<img src=# onerror=alert(17929)>"]
                        for v in vectors:  # 每注入一次攻击向量，页面刷新一次
                            d = d + 1
                            vector_value = v.value
                            print "注入第%d个XSS攻击向量:%s：".decode('utf-8').encode(type)%(d,(v.value).decode('utf-8').encode(type))
                            symbol = 0  #标记是否找到xss
                            f = self.getLatestForm(index, page_status)
                            [injects, submit] = self.parse_form(f)
                            injects[iji].clear()  #注入点,清空输入
                            injects[iji].send_keys(vector_value)
                            injects_html =  injects[iji].get_attribute('outerHTML') #form表单中的注入点html
                            #非注入点输入点填入普通字符串
                            test_str = self.make_unique_flag(6)
                            for j in xrange(len(injects)):
                                if j!=iji:
                                    injects[j].clear()
                                    injects[j].send_keys(test_str)
                            # 表单提交并判断XSS是否触发
                            re = self.submitandJudege(submit,injects,page_status)
                            if re: #XSS触发成功
                                # 保存漏洞信息
                                #      #form表单中的注入点html
                                self.results.append(self.formXSSInfo('form', vector_value,  injects_html))
                                break
                    else:
                        print "注入点不可注入".decode('utf-8').encode(type)
        except Exception as e:
            # print "xss_form报错：".decode('utf-8').encode(type),e
            pass
    #获取页面全部iframe
    def getIframes(self):
        try:
            iframes = self.driver.find_elements_by_tag_name('iframe')
            return  iframes
        except:
            return []

    # xss检测iframe中源码
    def iframe_xss_form(self):
        iframes = self.getIframes()  # 获取当前页面全部iframe
        print "iframe xss检测，页面iframe个数：".decode('utf-8').encode(type), len(iframes)
        # 遍历页面iframe,i标记处理的iframe
        for i in xrange(len(iframes)):
            iframes = self.getIframes()  # 重新获取最新iframe
            print "开始检测第%d个iframe".decode('utf-8').encode(type) % (i)
            self.driver.switch_to.frame(iframes[i])  # 切至iframe
            # xss iframe form
            try:
                forms = self.getFormEles()
                print "iframe%d中存在%d个表单".decode('utf-8').encode(type) % (i, len(forms))
                num_of_form = len(forms)
                # 检测每个form,f标记处理的form
                for index in xrange(num_of_form):
                    #获取表单注入点
                    iframe_form = self.getLatestForm(index, self.pageStatus())
                    [injects, submit] = self.parse_form(iframe_form)
                    # 依次遍历每个注入点
                    for iji in xrange(len(injects)):
                        # 切回原iframe
                        iframes = self.getIframes()  # 每次重新获取最新iframe
                        self.driver.switch_to.frame(iframes[i])
                        # 页面状态，是否可注入，输出点类型
                        (iframe_page_status, ii, out_point_dict) = self.isInputInjectable(iji, index)
                        self.accept_initial_alert(self.alert)
                        if ii:  # 可注入
                            print "注入点可注入!".decode('utf-8').encode(type)
                            print "输出点类型：".decode('utf-8').encode(type), out_point_dict
                            vectors = self.getallTypeVectors(out_point_dict)# 根据输出点类型选取攻击向量对象集 finalVector对象
                            print "待测攻击向量个数：".decode('utf-8').encode(type), len(vectors)
                            d = 0
                            for v in vectors:  # 每注入一次攻击向量，页面刷新一次
                                # 判断页面是否刷新,切入原iframe
                                iframes = self.getIframes()  # 每次重新获取最新iframe
                                self.driver.switch_to.frame(iframes[i])  # 切至对应iframe
                                iframe_form = self.getLatestForm(index,iframe_page_status)
                                d = d + 1
                                vector_value = v.value  # 具体的攻击向量字符串
                                print "注入第%d个XSS攻击向量:%s：".decode('utf-8').encode(type)%(d,(v.value).decode('utf-8').encode(type))
                                [injects, submit] = self.parse_form(iframe_form)
                                injects[iji].clear()  # 注入点,清空输入
                                injects[iji].send_keys(vector_value)
                                injects_html = injects[iji].get_attribute('outerHTML')  #iframe form表单中的注入点html
                                # 非注入点输入点填入普通字符串
                                test_str = self.make_unique_flag(6)
                                for j in xrange(len(injects)):
                                    if j != iji:
                                        injects[j].clear()
                                        injects[j].send_keys(test_str)
                                # 表单提交并判断XSS是否触发
                                re = self.submitandJudege(submit, injects, iframe_page_status)
                                if re:  # XSS触发成功
                                    # 保存漏洞信息
                                    self.results.append(self.formXSSInfo('iframe form', vector_value, injects_html))
                                    break
                            # 切回原iframe
                            iframes = self.getIframes()  # 每次重新获取最新iframe
                            self.driver.switch_to.frame(iframes[i])
            except Exception as e:
                # print 'iframe xss error:',e
                pass
    # ========================================== FORM XSS ===================================================
    # ======================================= 检测信息处理 ==================================================
    #构造检测到的漏洞信息:
    # 输入：type：url,input,form ；vector:检测成功的攻击向量；elem:注入点
    #输出:漏洞信息元组(漏洞所在页面URL,注入点类别,攻击向量， 注入点元素html)
    def formXSSInfo(self,type,vector,inject_html):
                  #漏洞所在页面URL     注入点类别  攻击向量      注入点元素html
        return (self.driver.current_url, type, vector,inject_html)

    #展示XSS检测结果
    def getResults(self):
        print '====','URL:',self.url,' 检测结束 ================='.decode('utf-8').encode(type)
        print 'URL: %sXSS 检测结果：'.decode('utf-8').encode(type)%(self.url)
        if self.results:
            print '共检测出%d个漏洞'.decode('utf-8').encode(type)%(len(self.results))
            for index,r in enumerate(self.results):
                print index+1,'XSS所在URL：'.decode('utf-8').encode(type),r[0]
                print '注入点类型：'.decode('utf-8').encode(type),r[1]
                print '攻击向量：'.decode('utf-8').encode(type), r[2].decode('utf-8').encode(type)
                if r[1] == 'url':
                    print '注入点:'.decode('utf-8').encode(type),r[3].decode('utf-8').encode(type)
                else:
                    print 'form表单中的注入点:'.decode('utf-8').encode(type), r[3].decode('utf-8').encode(type)
        else:
            print '未检测到XSS漏洞！'.decode('utf-8').encode(type)

#-------------------------------- run.py -----------------------------------------
#与用户交互的类，输入扫描网址，扫描深度
#输出XSS检测结果
class XSSer():
    def __init__(self,url,depth):
        self.url = url
        self.depth = depth
        self.thread = 15 #扫描线程数
        self.results = [] #存储检测结果
        self.total_request = 0 #记录总请求数
        self.detect_urls = [] #检测的URL
        self.path = os.getcwd()+"\\xssReport\\"+urlparse(self.url).hostname+"\\"#扫描结果保存路径
        self.start_time = ''#xss检测开始时间
        self.end_time = '' #XSS检测结束时间
        self.duration = ''#耗时
        self.makeDir(self.path)
        self.failed_url = [] #存储无法访问的URL

    #扫描实施
    def scan(self):
        # 代码运行开始时间：年月日 时分秒
        start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print '扫描开始时间：'.decode('utf-8').encode(type), start_time
        self.start_time = start_time
        # 代码运行开始计时标记
        start_sec = clock()
        #获取全部待检测url
        print '开始爬取网页链接....'.decode('utf-8').encode(type)
        links = CrawlThread(self.url).crawlDepth(self.depth, self.thread)
        if len(links) != 0:
            links  = list(set(links))
            self.detect_urls.extend(links)
            print '网页链接爬取完毕,爬取链接数：'.decode('utf-8').encode(type),len(links)
        #挨个检测各个url页面的XSS状况，多线程实施处
        print '开始XSS检测'.decode('utf-8').encode(type)
        d = 0
        for link in links:
            d = d+1
            print '开始检测第%d个URL：%s：'.decode('utf-8').encode(type)%(d,link)
            # generated_url = []
            xssDec = XSSDec(link)
            # self.total_request = self.total_request + xssDec.request
            self.results.extend(xssDec.start())
            # generated_url.extend(xssDec.crawled)
            for gu in xssDec.crawled:
                if gu not in links:
                    links.append(gu)
            #存储XSS检测中无法访问的链接：timeoutException 10s
            self.failed_url.extend(list(set(xssDec.faied_url)))
            xssDec.quit()  # 关闭页面，退出驱动
        print 'xss检测结束'.decode('utf-8').encode(type)
        finish_sec = clock() # 代码运行结束时间标记
        # 代码运行结束时间：年月日 时分秒
        end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print '结束时间：'.decode('utf-8').encode(type), end_time
        print  '历时：'.decode('utf-8').encode(type), self.sectohms(finish_sec - start_sec)
        self.end_time = end_time
        self.duration =self.sectohms(finish_sec - start_sec)
        self.getResults()
        self.saveResults2file()#保存检测结果至文件
        print '检测报告保存路径：'.decode('utf-8').encode(type),self.path + urlparse(self.url).hostname+self.end_time.replace(":","-")+ ".txt"
        self.saveCrawedURL()  # 保存爬取的链接至文件
        self.saveFailedURL()#保存爬取失败的链接至文件

    #展示XSS检测结果
    def getResults(self):
        print '============================ 检测结束，展示检测结果 =============================='.decode('utf-8').encode(type)
        print 'XSS检测结果：'.decode('utf-8').encode(type)
        if self.results:
            # print 'HTTP请求数：',self.total_request
            self.results = list(set(self.results)) #去除重复的漏洞
            print '可XSS检测链接数：%d'.decode('utf-8').encode(type) % (len(self.detect_urls))
            print '无法访问链接数：%d'.decode('utf-8').encode(type) % (len(self.failed_url))
            print '共检测出%d个漏洞'.decode('utf-8').encode(type) % (len(self.results))
            for index,r in enumerate(self.results):
                print '=========================================================='.decode('utf-8').encode(type)
                print index+1,'XSS所在URL：'.decode('utf-8').encode(type),r[0]
                print '注入点类型：'.decode('utf-8').encode(type),r[1]
                print '攻击向量：'.decode('utf-8').encode(type), r[2].decode('utf-8').encode(type)
                if r[1] == 'url':
                    print '注入点:'.decode('utf-8').encode(type),r[3].decode('utf-8').encode(type)
                else:
                    print 'form表单中的注入点:'.decode('utf-8').encode(type), r[3].decode('utf-8').encode(type)
        else:
            print '未检测到XSS漏洞！'.decode('utf-8').encode(type)

    #保存检测结果至本地txt文件中
    def saveResults2file(self):
        f = open(self.path + urlparse(self.url).hostname +self.end_time.replace(":","-")+ ".txt", 'w')
        f.write('=============== XSS Scanner参数配置 ===========================' + '\n')
        f.write('入口URL：' + self.url + '\n')
        f.write('URL检测深度：' + str(self.depth) + '\n')
        f.write('=============== XSS Scanner检测结果 ===========================' + '\n')
        f.write('检测URL数目：'+ str(len(self.detect_urls)) + '\n')
        f.write('检测出XSS漏洞数目：'+ str(len(self.results)) + '\n')
        f.write('XSS检测开始时间：'+self.start_time+ '\n')
        f.write('XSS检测结束时间：' + self.end_time + '\n')
        f.write('XSS检测耗时：' + self.duration + '\n')
        self.results = list(set(self.results))  # 去除重复的漏洞
        for index, r in enumerate(self.results):
            f.write('=========================================================='+ '\n')
            f.write(str(index+1)+'.XSS所在URL：'+r[0] + '\n')
            f.write('注入点类型：'+r[1] + '\n')
            f.write('攻击向量：'+r[2] + '\n')
            if r[1] == 'url':
                f.write('注入点:'+r[3] + '\n')
            else:
                f.write( 'form表单中的注入点:'+r[3] + '\n')
        f.close()

    #保存检测的URL至文件中
    def saveCrawedURL(self):
        f = open(self.path + "detected_urls"+self.end_time.replace(":","-")+".txt", 'w')
        f.write('共检测URL：'+str(len(self.detect_urls)) + '\n')
        for link in self.detect_urls:
            f.write('爬取的URL：'+link+'\n')
        f.close()

    #保存XSS检测中访问失败的链接
    def saveFailedURL(self):
        f = open(self.path + "failed_urls" + self.end_time.replace(":", "-") + ".txt", 'w')
        f.write('访问失败URL数目：' + str(len(self.failed_url)) + '\n')
        for link in self.failed_url:
            f.write('失败链接：' + link + '\n')
        f.close()

    # 创建指定路径下的文件夹
    def makeDir(self,path):
        try:
            os.makedirs(path)
        except OSError:
            if not os.path.isdir(path):
                raise

    # 秒数转时分秒函数
    def sectohms(self,seconds):
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        return "%02d:%02d:%02d" % (h, m, s)

if __name__ == '__main__':
    url1 = 'http://testphp.vulnweb.com/'
    url2 = 'http://www.kinwong.com/Catalog_105.aspx?query=d'
    url3 = 'http://localhost:8088/dvwa/vulnerabilities/xss_s/'
    url4 = 'http://testphp.vulnweb.com/signup.php'#未检测出页面漏洞：点击之后页面跳转是新URL页面
    ##cmd交互
    print "脚本名称：".decode('utf-8').encode(type), sys.argv[0]#python指令后的第一个参数
    url = sys.argv[1] #检测URL
    depth = int(sys.argv[2]) #检测深度
    # url = url1
    # depth = 2
    print "检测URL".decode('utf-8').encode(type), ":",url
    print "检测深度".decode('utf-8').encode(type), ":", depth
    x = XSSer(url, depth).scan()
