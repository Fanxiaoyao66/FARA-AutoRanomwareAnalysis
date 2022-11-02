import os
from config_r import base_path,shell_path


def Run_Shell(path):
    folder_names = os.listdir(path)

    for folder_name in folder_names:
        folder_path = os.path.join(path,folder_name)
        file_names = os.listdir(folder_path)

        for file_name in file_names:
            ransomware_name = os.path.join(folder_path,file_name)
            output = os.popen("{} {}".format(shell_path,ransomware_name))
            print(output.read())
            print("-------------------------------------------")




Run_Shell(base_path)