from fileinput import filename
import os
import zipfile
import pyzipper

from config_r import base_path,password

def Decompression_Files(path):

    flag_ransomware = 0
    flag_sample_suc = 0
    flag_sample_fail = 0

    folder_names = os.listdir(path)
    # print(folder_names)

    #目录下新建文件夹存放解压后勒索软件
    decompression_path = os.path.join(path,'../Decompression-Ransomware-total1')
    if os.path.isdir(decompression_path):
        pass
    else:
        os.mkdir(decompression_path)

    #第一层文件夹（勒索软件名）
    for folder_name in folder_names:
        folder_path = os.path.join(path,folder_name)
        file_names = os.listdir(folder_path)
        decompression_file_path = os.path.join(decompression_path,folder_name.replace(' ',''))

        #在解压目录为每个勒索软件设置一个文件夹
        if os.path.isdir(decompression_file_path):
            pass
        else:
            os.mkdir(decompression_file_path)
 
        #遍历文件夹中勒索软件压缩包（样本）
        for file_name in file_names:
            ransomware_path = os.path.join(folder_path,file_name)
            
            #解压
            decompression_ransomware = pyzipper.AESZipFile(ransomware_path,'r',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES)
            try:
                decompression_ransomware.extractall(path = decompression_file_path,pwd = str.encode(password))
                flag_sample_suc = flag_sample_suc + 1
            except:
                flag_sample_fail = flag_sample_fail + 1

            # # decompression_ransomware = zipfile.ZipFile(ransomware_path,'r')
            # decompression_ransomware.extractall(path = decompression_file_path,pwd=b'infected')
        flag_ransomware = flag_ransomware + 1
    print("---------------------------------------------------")
    print("成功解压 {} 个勒索软件家族中的 {} 个样本，失败 {} 个".format(flag_ransomware,flag_sample_suc,flag_sample_fail))
    print("---------------------------------------------------")

# def Decompression_Files_twice(path):
#     folder_names = os.listdir(path)
#     for folder_name in folder_names:
#         folder_path = os.path.join(path,folder_name)
#         file_names = os.listdir(folder_path)
#         for file_name in file_names:
#             if(file_name[:-4:-1] == 'zip'):



Decompression_Files(base_path)
