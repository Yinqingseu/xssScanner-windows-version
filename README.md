# xssScanner
python编写的的xss漏洞检测工具，selenium
1.	运行环境配置
  xssScanner运行系统：windows 64位
  开发语言：python
  开发工具：pycharm
  xssScanner运行所需环境如下1-5所示：
  1). python 2.7
  2). mysql5.6  ：执行xssScanner/installer/database.sql创建所需数据库并导入数据
  3). firefox 59版本 
  4). python库：
          protobuf（3.0.0）
          mysql-connector-python（2.1.3）
      lxml（4.2.1）
      selenium (3.6.0)
  5). selenium 火狐浏览器驱动geckodriver 0.20.1
 mysql执行database.sql文件，实现数据库的创建和检测数据的导入。

2.	使用说明
2.1 工具使用方法
cmd打开到xssScanner/xssScanner.py目录下，输入命令：
python xssScanner.py [url] [depth]
其中脚本入口参数：
[url]表示待测url     
[depth]表示检测深度，采用广度优先遍历的爬虫策略，建议检测深度不要超过5
两个参数以空格分开，缺一不可。
例如：
设置检测URL：http://testphp.vulnweb.com/signup.php，检测深度为3的命令：
python xssScanner.py http://testphp.vulnweb.com/ 3
2.1 扫描结果
扫描结果保存路径：xssScanner文件路径\xssReport\检测url主机名\
该路径包括三种文件：
	detected_urls检测时间.txt ------ 存储检测的URL
	failed_urls检测时间.txt ------- 存储检测失败的URL
	检测网站url检测时间.txt ------- 存储检测URL的xss漏洞检测信息
xssScanner检测结果示例部分展示：
 
2.3 数据库xsspayloads
xssScanner采用黑盒检测技术，用于XSS检测的攻击向量存储至mysql数据库中，完成安装此工具的用户可通过用户名：xssScanner_user和密码：yinqing1登录mysql，XSS检测的攻击向量存储至数据库xsspayloads中，该数据库中共有4张表：
	表initial_xss_payloads -------- 存储初始XSS攻击向量
	表payloads_type_intro ------- 存储攻击向量类别说明
	表mutated_xss_payloads -------- 存储变异XSS攻击向量
	表mutate_rules_intro ----- 存储变异规则说明
2.4 xssScanner的扩展性
xssScanner采用攻击向量与检测程序分离的设计方法，xssScanenr检测所用的xss攻击向量为表mutated_xss_payloads中的内容。
用户可根据需求，增删数据表mutated_xss_payloads中各个类别xss攻击向量的内容，改进xssScanner。

