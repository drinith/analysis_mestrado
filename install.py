import subprocess


solc_dic = {'4':'0.4.26','5':'0.5.17','6':'0.6.12','7':'0.7.6','8':'0.8.23'}

subprocess.run('pip','install','-r','requirements.txt')


for i in solc_dic:
    subprocess.run('solc-selct','install',i)