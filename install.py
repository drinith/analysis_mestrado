import subprocess


solc_dic = {'4':'0.4.26','5':'0.5.17','6':'0.6.12','7':'0.7.6','8':'0.8.23'}

subprocess.run('pip install -r requirements.txt', capture_output=True, text=True,shell=True)


for i in solc_dic:
    subprocess.run(f'solc-select install {solc_dic[i]} ',capture_output=True, text=True,shell=True)