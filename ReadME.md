### [FARA-AutoRanomwareAnalysis](https://github.com/Fanxiaoyao66/FARA-AutoRanomwareAnalysis)

---

**本项目旨在自动化分析提取勒索软件IAT表和导入函数共学术分析使用**

**How to install：**

- 1、将[RansomwareTotal](https://github.com/Fanxiaoyao66/RansomwareTotal)项目下的勒索软件Total下载到本地

- 2、修改Decompression_Files文件夹中config_r.py中的base_path为勒索软件Total的绝对路径
- 3、编译API_FROM_IAT.cpp
- 4、修改Decompression_Files文件夹中config_r.py中的shell_path为API_FROM_IAT.exe的绝对路径
- 5、运行Decompression_Files.py解压所有勒索软件（密码默认：infected，config_r.py修改）
- 6、运行Run_shell.py自动提取IAT表和导入函数，在每个勒索软件目录下生成txt文档

