import pymysql
import json
import time
import random
import string
import base64
import hashlib


def database_connector():  # 连接数据库
    db = pymysql.connect("host", "user", "password", "table", charset='utf8')
    print(db)
    return db


def FindUser(type, username):
    db = database_connector()
    cursor = db.cursor()
    if type == 0:
        sql = "SELECT * FROM user where username = '" + username + "'"
    elif type == 1:
        sql = "SELECT * FROM user where email = '" + username + "'"
    elif type == 2:
        sql = "SELECT * FROM user where phone = '" + username + "'"
    else:
        return False
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results[0]


def login(type, username, password):
    userinfo = FindUser(type, username)
    if userinfo == False:
        return False
    if password == userinfo[3]:
        return userinfo[14]  # 返回用户类型
    else:
        return -1


def api_userqueryAll():
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM user"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def api_userDirectionQueryAll():
    db = database_connector()
    cursor = db.cursor()

    sql = "select direction from user group by direction"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def api_userquery(type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM user where " + type + " LIKE '" + value + "'"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def api_userNamequery(type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT realname FROM user where " + type + " LIKE '" + value + "'"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def api_scorequery(type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM paper where " + type + " LIKE '" + str(value) + "'"
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        res = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()

    if len(res) == 0:
        return False
    return res


def api_scorequeryAll():
    db = database_connector()
    cursor = db.cursor()

    sql = "select user.realname, user.number, topic.t_topic, paper.op_score, paper.mi_score, paper.th_score, paper.score from user,topic,paper where user.number = topic.t_snumber and topic.id = paper.topic_id group by user.number, topic.t_topic, paper.op_score, paper.mi_score, paper.th_score, paper.score"
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def api_topicquery(type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM topic where " + type + " LIKE '" + value + "'"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def api_paperquery(type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM paper where " + type + " LIKE '" + str(value) + "'"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def api_updateScore(topic_id, type, score):
    db = database_connector()
    cursor = db.cursor()

    sql = "update paper set %s = %s where topic_id=%s" % (str(type), str(score), str(topic_id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_usermodify(id, username, password, sex, SQLclass, t_class, number, college, direction, title, realname,
                   portrait,
                   intro, category, frequency, phone, qq, email, wechat, lock):
    db = database_connector()
    cursor = db.cursor()

    sql = "update user set username = '%s', password = '%s', sex = '%d', class = '%s', t_class = '%s', number = '%s', college = '%s', direction = '%s', title = '%s', realname = '%s', portrait = '%s', intro = '%s', category = '%s', frequency = '%s', phone = '%s', qq = '%s', email = '%s', wechat = '%s', `lock` = '%s' WHERE id = %d" % (
        username, password, int(sex), SQLclass, t_class, number, college, direction, title, realname, portrait, intro,
        category,
        frequency, phone, qq, email, wechat, lock, int(id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_user_add(uid, username, password, sex, SQLclass, t_class, number, college, direction, title, realname,
                 portrait,
                 intro, category, frequency, phone, qq, email, wechat, lock, modify):
    db = database_connector()
    cursor = db.cursor()
    password = hashlib.md5(password.encode(encoding='UTF-8')).hexdigest()
    sql = "INSERT INTO user(`uid`, `username`, `password`, `sex`, `class`, `t_class`, `number`, `college`, `direction`, `title`, `realname`, `portrait`, `intro`, `category`, `frequency`, `phone`, `qq`, `email`, `wechat`, `lock`, `modify`) VALUES ('%s', '%s',  '%s',  '%s',  '%s', '%s', '%s',  '%s',  '%s',  '%s','%s', '%s',  '%s',  '%s',  '%s','%s', '%s',  '%s',  '%s',  '%s', '%s')" % (
        uid, username, password, sex, SQLclass, t_class, number, college, direction, title, realname,
        portrait,
        intro, category, frequency, phone, qq, email, wechat, lock, modify)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def admin_user_findpass_api(status=0):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM forgetPasswordList where status=%d" % (status)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def admin_user_findpassdetails_api(id):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM forgetPasswordList where id=%d" % (int(id))

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results[0]


def admin_user_changePassword(id, pwd):
    db = database_connector()
    cursor = db.cursor()
    pwd = hashlib.md5(pwd.encode(encoding='UTF-8')).hexdigest()
    sql = "update user set password='" + str(pwd) + "' WHERE id=" + str(id)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def admin_user_changePassword_updateStatus(id, s=1):
    db = database_connector()
    cursor = db.cursor()
    sql = "update forgetPasswordList set status=" + str(s) + " WHERE id=" + str(id)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def admin_user_changePassword_CountAll():
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT COUNT(*) FROM forgetPasswordList"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results[0][0]


def admin_user_query_count():
    db = database_connector()
    cursor = db.cursor()
    user = 0
    teacher = 0
    student = 0
    sql = "SELECT COUNT(*) FROM user"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    user = results[0][0]
    sql = "SELECT COUNT(category) FROM user where category = 3"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    student = results[0][0]
    sql = "SELECT COUNT(category) FROM user where category = 10"

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    teacher = results[0][0]

    db.close()
    if len(results) == 0:
        return False
    jso = [user, teacher, student]
    return jso


def api_verifycode_insert(uid, code, vc_type):
    iat = int(time.time())
    exp = int(time.time() + 300)
    db = database_connector()
    cursor = db.cursor()
    sql = "INSERT INTO verifyCode(`uid`, `code`, `iat`, `exp`, `vc_type`) VALUES ('%s', '%s', '%s', '%s', '%s')" % (
        uid, code, iat, exp, vc_type)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def insert_forget(name,number,phone,email,useragent):
    iat = int(time.time())
    db = database_connector()
    cursor = db.cursor()
    sql = "INSERT INTO forgetPasswordList(`name`, `number`, `phone`, `email`, `userAgent`,`time`) VALUES ('%s', '%s', '%s', '%s', '%s', NOW())" % (
        name,number,phone,email,useragent)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def api_verifycode_verify(uid, code):
    db = database_connector()
    cursor = db.cursor()
    iat = int(time.time())
    exp = int(time.time())
    sql = "SELECT * FROM verifyCode where `uid`=%s and `code`=%s and `iat` <= %s and `exp` > %s and `status` = 1" % (
        uid, code, iat, exp)
    # print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return True


def api_verifycode_setUsed(code):
    db = database_connector()
    cursor = db.cursor()
    sql = "update verifyCode set status=0 WHERE code=" + code

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False


def CommonQuery(table, type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM " + table + " where " + type + " LIKE '" + value + "'"
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    print(results)
    if len(results) == 0:
        return False
    return results


def CommonQueryAll(table):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM " + table
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def api_notice_insert(title, user, text, author):
    times = time.asctime(time.localtime(time.time()))
    print(times)
    db = database_connector()
    cursor = db.cursor()
    sql = "INSERT INTO notice (`name`, `text`, `authors_number`, `time`, `group`) VALUES ('%s', '%s', '%s',NOW(), '%s')" % (
        title, text, author, user)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_updateNoticeRead(id):
    db = database_connector()
    cursor = db.cursor()

    sql = "update notice set `read` = `read` + 1 where id=%s" % (str(id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_updateNotice(id, title, text):
    db = database_connector()
    cursor = db.cursor()

    sql = "update notice set `name`='%s', `text`='%s' where `id`=%s" % (str(title), str(text), str(id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_Deletenotice(nid):
    db = database_connector()
    cursor = db.cursor()

    sql = "update notice set `display`=0 where `id`=%s" % (str(nid))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_advice_insert(auth_num, receive_type, rece_num, title, text, auth_name, rece_name):
    times = time.asctime(time.localtime(time.time()))
    print(times)
    db = database_connector()
    cursor = db.cursor()
    sql = "INSERT INTO advice (`auth_num`, `receive_type`, `rece_num`, `title`, `text`, `read`, `time`,`auth_name`, `rece_name`) VALUES ('%s', '%s', '%s','%s','%s','%s',NOW(),'%s','%s')" % (
        auth_num, receive_type, rece_num, title, text, 0, auth_name, rece_name)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_updateAdviceReply(id, reply):
    db = database_connector()
    cursor = db.cursor()

    sql = "update advice set `reply`='%s', `reply_time`= NOW() WHERE `id`='%s'" % (str(reply), str(id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def recentChatObjectSelect(uid):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM chat where (auth='" + uid + "' or rece = '" + uid + "') and display = 1"
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    ChatObject = {}
    for i in results:
        if i[1] == uid:
            ChatObject[i[2]] = i[4]
            continue
        if i[2] == uid:
            ChatObject[i[1]] = i[3]
            continue
    return ChatObject


def recentChatObjectSelectRead(uid):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM chat where rece = '" + uid + "' and `read` = 0 and display = 1"
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    ChatObject = []
    for i in results:
        ChatObject.append(i[1])
    lists = list(set(ChatObject))
    return lists


def chatUpdate(id):
    db = database_connector()
    cursor = db.cursor()

    sql = "update chat set `read`=1 WHERE `id`='%s'" % (str(id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def chatRebackUpdate(id):
    db = database_connector()
    cursor = db.cursor()

    sql = "update chat set `display`=0 WHERE `id`='%s'" % (str(id))
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def chatObjectAll(uid, oid):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT * FROM chat where ((auth='" + uid + "' and rece = '" + oid + "') or (rece = '" + uid + "' and auth = '" + oid + "')) and `display` = 1"
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()
    for i in results:
        if i[7] == 0 and i[2] == uid:
            chatUpdate(i[0])
    if len(results) == 0:
        return False
    return results


def chatSendMessage(uid, oid, text, auth_name):
    db = database_connector()
    cursor = db.cursor()
    rece_name = api_userquery('uid', oid)
    print(oid)
    sql = "INSERT INTO chat (`auth`, `rece`, `auth_name`, `rece_name`, `text`, `time`) VALUES ('%s', '%s', '%s','%s','%s',NOW())" % (
        uid, oid, auth_name, rece_name[0][11], text)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def topic_add(title=None, tea=None, stu=None):
    db = database_connector()
    cursor = db.cursor()

    sql = "INSERT INTO topic (`t_snumber`, `t_topic`, `t_tnumber`) VALUES ('%s', '%s', '%s')" % (
        stu, title, tea)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False
    topic_paper_unionQuery(stu, tea)
    # 关闭数据库连接
    db.close()
    return True

def topic_paper_unionQuery(sn,tn):
    db = database_connector()
    cursor = db.cursor()

    sql = "SELECT id FROM topic where t_snumber = %s and t_tnumber = %s" % (sn,tn)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        paper_add(results[0][0])
    except:
        print("在程序执行中发生了错误")

    db.close()
    if len(results) == 0:
        return False

    return results

def topic_paper_unionQuerySN(sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.*,p.* from topic as t left join paper p on t.id = p.topic_id where t.t_snumber = '%s'" % (sn)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")

    db.close()
    if len(results) == 0:
        return False

    return results


def choose_topicQuery():
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.*, u.realname from topic as t left join user as u on t.t_tnumber=u.number where  t.t_snumber = -1"
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")

    db.close()
    if len(results) == 0:
        return False

    return results

def paper_add(tid):
    db = database_connector()
    cursor = db.cursor()

    sql = "INSERT INTO paper (`topic_id`) VALUES ('%s')" % (tid)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def topic_query():
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.*, u1.realname as student_name,u2.realname as teacher_name from topic as t left join user as u1 on t.t_snumber = u1.number left join user as u2 on t.t_tnumber = u2.number group by t.id"
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")
    db.close()

    if len(results) == 0:
        return False
    return results

def api_topicquery(type, value):
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.*, u1.realname as student_name,u2.realname as teacher_name from topic as t left join user as u1 on t.t_snumber = u1.number left join user as u2 on t.t_tnumber = u2.number where %s LIKE '%s' group by t.id" % (type, value)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def api_topicmodify(id,  sn, title, tn):
    db = database_connector()
    cursor = db.cursor()

    sql = "update topic set t_snumber = '%s', t_topic = '%s', t_tnumber = '%s' WHERE id = %s" % (sn, title, tn,id)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def api_StudentChooseTopic(sn,tid):
    db = database_connector()
    cursor = db.cursor()

    sql = "update topic set t_snumber = '%s' WHERE id = %s" % (sn, tid)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def api_UpdatePaperUpload(tid, type, value):
    db = database_connector()
    cursor = db.cursor()
    str_type = ''
    if type != '1' and type != '2' and type != '3':
        return False
    if type == '1':
        str_type = 'open'
        date = 'op_date'
    elif type == '2':
        str_type = 'middle'
        date = 'mi_date'
    elif type == '3':
        str_type = 'thesis'
        date = 'th_date'
    else:
        return False
    print(tid, str_type, value)
    sql = "update paper set %s = '%s', %s = NOW() WHERE topic_id = %s" % (str_type, value, date, tid)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def api_docsQueryAll(kaidan):
    l = ''
    s = ''
    if kaidan == 'open':
        l = 'open'
        s = 'op'
    if kaidan == 'middle':
        l = 'middle'
        s = 'mi'
    if kaidan == 'thesis':
        l = 'thesis'
        s = 'th'
    db = database_connector()
    cursor = db.cursor()

    sql = "select p.topic_id,t.t_topic,p.%s,p.%s_date,p.%s_score,u1.realname as student_name,u1.number,u2.realname as teacher_name,u2.number, u1.returned from paper as p left join topic as t on p.topic_id = t.id left join user as u1 on t.t_snumber = u1.number left join user as u2 on t.t_tnumber = u2.number group by t.id"%(l,s,s)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def defendUserGroupSelectAll():
    db = database_connector()
    cursor = db.cursor()

    # sql = "select t_class from paper as p left join topic as t on p.topic_id = t.id left join user as u1 on t.t_snumber = u1.number where p.thesis != '' and p.returned != 1 group by u1.t_class"
    sql = "SELECT college, direction from user group by direction"
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results


def defend_add(title, time, content, user):
    db = database_connector()
    cursor = db.cursor()

    sql = "INSERT INTO defend (`title`, `time`, `content`,`college`) VALUES ('%s', '%s', '%s', '%s')" % (
        title, time, content, user)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def defend_score_add(did, college):
    db = database_connector()
    cursor = db.cursor()

    # sql = "select t_class from paper as p left join topic as t on p.topic_id = t.id left join user as u1 on t.t_snumber = u1.number where p.thesis != '' and p.returned != 1 group by u1.t_class"
    sql = "select u.number, t.t_topic,t.id from topic as t left join user as u on u.number = t.t_snumber where college = '%s'" % (college)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
    except:
        print("在程序执行中发生了错误")

    for i in results:
        sql = "INSERT INTO defend_score (`defend_id`, `student_number`, `topic_id`) VALUES ('%s', '%s', '%s')" % (
            did,i[0],i[2])
        print(sql)
        try:
            # 执行SQL语句
            cursor.execute(sql)
            # 提交数据库执行
            db.commit()
        except pymysql.Error as e:
            print(e.args[0], e.args[1])
            # 错误时回滚
            db.rollback()
            return False

    db.close()
    if len(results) == 0:
        return False
    return True

def api_defendSigninStatusChange(id, flag):
    db = database_connector()
    cursor = db.cursor()

    sql = "update defend set signinStatus = %s WHERE id = %s" % (flag, id)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def defendQueryPeopleNumber():
    db = database_connector()
    cursor = db.cursor()

    # sql = "select t_class from paper as p left join topic as t on p.topic_id = t.id left join user as u1 on t.t_snumber = u1.number where p.thesis != '' and p.returned != 1 group by u1.t_class"
    sql = "select d.*, s.defend_id, count(s.defend_id),count(ss.score),count(s3.sign_in) from defend_score as s left join defend_score as ss on ss.id = s.id and ss.score != 0 left join defend_score as s3 on s3.id = s.id and s3.sign_in != 0 left join defend d on s.defend_id = d.id group by s.defend_id"
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def api_defendQueryResult(id):
    db = database_connector()
    cursor = db.cursor()

    # sql = "select t_class from paper as p left join topic as t on p.topic_id = t.id left join user as u1 on t.t_snumber = u1.number where p.thesis != '' and p.returned != 1 group by u1.t_class"
    sql = "select ds.*, u.realname, t.t_topic,u.id from defend_score as ds left join topic as t on t.id = ds.topic_id left join user as u on ds.student_number = u.number where defend_id = %s" % (id)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results



def teacher_StudentQuery(id):
    db = database_connector()
    cursor = db.cursor()

    sql = "select u.*,t.t_snumber,t.t_tnumber from user as u left join topic as t on u.number = t.t_snumber where t.t_tnumber = '%s'" %(id)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def defend_signin_insert(uid, tuid, useragency,sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "INSERT INTO signin_log (`student_uid`, `teacher_uid`, `signin_time`,`user_agency`) VALUES ('%s', '%s', NOW(), '%s')" % (
        uid,tuid,useragency)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    sql = "update defend_score set sign_in = 1, signin_time = NOW() WHERE student_number = %s" % (sn)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def teacher_SelectSigninLastOne(tuid):
    db = database_connector()
    cursor = db.cursor()

    sql = "select * from signin_log where teacher_uid = '%s' order by id desc limit 0,1" %(tuid)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")

    sql = "select u.id, t.id, u.number, u.realname, t.t_topic, p.op_score, p.mi_score, p.th_score, p.open,p.middle, p.thesis from user as u left join topic as t on u.number = t.t_snumber left join paper as p on t.id = p.topic_id where u.uid = '%s'" % (results[0][1])

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")

    db.close()
    if len(results) == 0:
        return False
    return results

def defend_score_update(sn,score):
    db = database_connector()
    cursor = db.cursor()

    sql = "update defend_score set score = %s WHERE student_number = %s" % (score,sn)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def returned_update(sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "update user set returned = '1' WHERE number = %s" % (sn)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True


def student_topicQuery(sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.t_topic,u.realname, p.op_score, p.op_date,p.open,t.id from topic as t left join user as u on t.t_tnumber = u.number left join paper as p on t.id = p.topic_id where t.t_snumber = '%s'"%(sn)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def student_topicQueryMiddle(sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.t_topic,u.realname, p.mi_score, p.mi_date,p.middle,t.id,p.op_score from topic as t left join user as u on t.t_tnumber = u.number left join paper as p on t.id = p.topic_id where t.t_snumber = '%s'"%(sn)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def student_topicQueryThesis(sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "select t.t_topic,u.realname, p.th_score, p.th_date,p.thesis,t.id,p.op_score,p.mi_score,p.th_score from topic as t left join user as u on t.t_tnumber = u.number left join paper as p on t.id = p.topic_id where t.t_snumber = '%s'"%(sn)

    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 获取所有记录列表
        results = cursor.fetchall()
        print(results)
    except:
        print("在程序执行中发生了错误")
    db.close()
    if len(results) == 0:
        return False
    return results

def returned_set0(sn):
    db = database_connector()
    cursor = db.cursor()

    sql = "update user set returned = '0' WHERE number = %s" % (sn)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True

def recordLogin(uid, useragent, ip):
    db = database_connector()
    cursor = db.cursor()

    sql = "INSERT INTO login_log (`uid`, `useragent`, `ip`,`time`) VALUES ('%s', '%s', '%s', NOW())" % (
        uid, useragent, ip)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    sql = "update user set lastlogin = NOW() WHERE uid = %s" % (uid)
    print(sql)
    try:
        # 执行SQL语句
        cursor.execute(sql)
        # 提交数据库执行
        db.commit()
    except pymysql.Error as e:
        print(e.args[0], e.args[1])
        # 错误时回滚
        db.rollback()
        return False

    # 关闭数据库连接
    db.close()
    return True