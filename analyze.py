#-*- coidng:utf-8 -*-

import sys
import os
import re

def main(argv):
    if len(argv) == 2 and os.path.exists(argv[0]) and os.path.exists(argv[1]):
        print('start analysis!')
        apks_list = os.listdir(argv[0])
        for i in apks_list:
            print('Analyzing %s' % str(i))
            #get versioncode, packagename, versionname
            path_to_apk = argv[0] + i
            output = os.popen("aapt d badging %s" % path_to_apk).read()
            match = re.compile("package: name='(\S+)' versionCode='(\d+)' versionName='(\S+)'").match(output)
            if not match:
                print(match)
                raise Exception('cannot get packageinfo')
                continue

            packagename = match.group(1)
            versioncode = match.group(2)
            versionname = match.group(3)

            file_result = open(argv[1] + str(i) + '.txt', 'a+')
            file_result.write("PackageName: %s \n" % packagename)
            file_result.write("VersionCode: %s \n" % versioncode)
            file_result.write("VersionName: %s \n" % versionname)

            #get permissions
            file_result.write("Permissions:\n")
            outlist = output.split('\n')
            for line in outlist:
                if line.startswith('uses-permission:'):
                    file_result.write(line.split('=')[1] + '\n')
            file_result.write('Network Traffic Flow:\n')
            file_result.close()

            #install app
            cmd = 'adb install %s' % (argv[0] + str(i))
            output_install = os.popen(cmd).read()
            if 'Success' in output_install:
                print('Success To Install App!')
            else:
                print(output_install.split('\n')[-2])


            #generate python script
            file_path = open('script.py', 'w')
            file_path.write('import os\n'
                            'file = \'%s\'\n' % (argv[1] + str(i) + '.txt') + '\n'
                                          'def request(flow):\n'
                                          '    file_flow = open(file, \'a+\')\n'
                                          '    file_flow.write(str(flow.request.headers) + \'\\n\')\n'
                                          '    file_flow.close()')
            file_path.close()

            #initial mitmdump
            os.popen('nohup mitmdump -s script.py &')

            #a = input()
            #monkey test
            cmd_moneky = 'adb shell monkey -p %s --ignore-crashes --pct-touch 10  --pct-motion 10 --pct-trackball 20  --pct-nav 30 --pct-majornav 30 --throttle 10000 30' % (packagename)
            print(os.popen(cmd_moneky).read())

            #kill mitmdump
            cmd = 'ps -ef | grep mitm'
            output = os.popen(cmd).read()
            pid = output.split('\n')[0].split(' ')[6]
            print(pid)
            cmd_kill = 'kill %s' % pid
            os.popen(cmd_kill)

            #remove script.py
            cmd_rm = 'rm -rf script.py'
            os.popen(cmd_rm)

            #uninstall app
            cmd_uninstall = 'adb uninstall %s' % packagename
            print(cmd_uninstall)
            print(os.popen(cmd_uninstall).read())







            print('Analyze Finished!')



    else:
        print('Arguments Error! OR No such dir!\n')
        print('usage: python3 analyze.py apks_dir results_dir')
        sys.exit()

if __name__ == '__main__':
    main(sys.argv[1:])
