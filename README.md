# App_Flow_Analyzer

### Monkey + Mitmproxy
##### 使用mitmproxy作为代理服务器，通过monkey完成自动化测试，抓取手机app的数据包

### 测试环境：
- PC： vmware虚拟机， ubuntu20.04， 安装ADB，aapt等工具，Python3
- 手机： Nexus 5X

### Steps:
- ##### 调试网络，使PC和测试用手机处于同一subnet；
- ##### 搭建mitmproxy代理，参考 <https://www.jianshu.com/p/0cc558a8d6a2>

- ##### 执行命令：
          git clone https://github.com/lecision/App_Flow_Analyzer.git
          python3  analyze.py  apks_directory  results_directory
		  			apks_direcotry(存放待分析app的目录)
					  results_directory(存放分析结果的目录)
