import xlrd
import main.document.excel as excel
import time, random
import main.database.base_database as bd


def addUserFromExcel(path):
    data = excel.queryExcel(path)
    for i in data:
        uid = int(time.time()) + int(random.random() * 10000000)
        if i[6] == '男':
            sex = 1
        else:
            sex = 2
        bd.api_user_add(uid, str(int(i[2])), str(i[7])[12:], sex, i[1], i[1], str(int(i[2])), i[8], i[8], '', i[0], '', '', 3, 0, str(i[3]), str(i[4]), str(i[5]), '', 0, 1)

#        (uid, username, password, sex, SQLclass, t_class, number, college, direction, title, realname,
#                  portrait,
#                  intro, category, frequency, phone, qq, email, wechat, lock, modify)

# addUserFromExcel('../../upload/UploadUserInfo/17s.xlsx')
