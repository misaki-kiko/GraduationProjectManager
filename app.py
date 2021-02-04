from flask import Flask, render_template, make_response, flash, Response
from flask import request, jsonify
from flask import redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import main.database.base_database
import main.email.mailmain
import main.document.excel
import main.message.mes
import main.login.base
import main.document.user
import main.config.base as conb
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
import random, time
import hashlib
import base64
import main.login.dkey as dkey
import webbrowser

app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"]
)
app.config['JSON_AS_ASCII'] = False


@app.route('/')
def hello_world():
    return render_template('login.html')


@app.route('/upload_user_img', methods=['POST', 'GET'])
def upload_user_img():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join('upload/UserImage', filename))
            return '{"filename":"%s"}' % filename
    return jsonify(), 201


@app.route('/upload_user_info', methods=['POST', 'GET'])
def upload_user_info():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join('upload/UploadUserInfo', filename))
            return jsonify(main.document.excel.queryExcel('upload/UploadUserInfo/%s' % (filename)))
    return jsonify(), 201


@app.route('/loginVerify', methods=['POST'])
def login():
    if conb.getConfig('loginpermission') == 0:
        return jsonify({"errno": 1004, "errmsg": "管理员关闭了用户登录功能，详情参见帮助页面"}), 201
    un = request.form['un']
    pw = hashlib.md5(request.form['pw'].encode(encoding='UTF-8')).hexdigest()
    login_type = 0  # 登陆方式：0用户名 1邮箱 2手机号
    query_login_type = 'username'
    if len(un) == 11 and un[0] == '1':
        login_type = 2
        query_login_type = 'phone'
    elif '@' in un:
        login_type = 1
        query_login_type = 'email'
    else:
        login_type = 0
    # 这个地方应该连数据库查询了
    type = main.database.base_database.login(login_type, un, pw)
    print(type)
    if type == False:
        return jsonify({"errno": 1005, "errmsg": "用户不存在，详情参见帮助页面"}), 201
    # 记录用户登录

    if type == 3:  # 学生
        userInfo = main.database.base_database.api_userquery(query_login_type, un)[0]
        response = make_response(redirect('/student'))
        response.set_cookie('token', main.login.base.JWTCreater("3", str(userInfo[1])))
        response.set_cookie('username', userInfo[2])
        response.set_cookie('uid', userInfo[1])
        response.set_cookie('id', str(userInfo[0]))

        useragent = request.headers.get("User-Agent")
        ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        recordLogin = main.database.base_database.recordLogin(userInfo[1], useragent, ip)

        return response
    elif type == 10:  # 教师
        userInfo = main.database.base_database.api_userquery(query_login_type, un)[0]
        response = make_response(redirect('/teacher'))
        response.set_cookie('token', main.login.base.JWTCreater("10", str(userInfo[1])))
        response.set_cookie('username', userInfo[2])
        response.set_cookie('uid', userInfo[1])
        response.set_cookie('id', str(userInfo[0]))

        useragent = request.headers.get("User-Agent")
        ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        recordLogin = main.database.base_database.recordLogin(userInfo[1], useragent, ip)

        return response
    elif type == 99:  # 管理员
        userInfo = main.database.base_database.api_userquery(query_login_type, un)[0]
        response = make_response(redirect('/admin'))
        response.set_cookie('token', main.login.base.JWTCreater("1", str(userInfo[1])))
        response.set_cookie('username', userInfo[2])
        response.set_cookie('uid', userInfo[1])
        response.set_cookie('id', str(userInfo[0]))

        useragent = request.headers.get("User-Agent")
        ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        recordLogin = main.database.base_database.recordLogin(userInfo[1], useragent, ip)

        return response
    elif type == 0:  # 不允许登陆
        return jsonify({"errno": 1002, "errmsg": "用户被禁止登陆，详情参见帮助页面或联系系统管理员"}), 201
    elif type == -1:
        return jsonify({"errno": 1001, "errmsg": "用户名或密码不正确，详情参见帮助页面或联系系统管理员"}), 201
    else:
        return redirect('/')


@app.route('/api/dkey', methods=['get'])
def api_dkey():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return jsonify({'key': '000000', 'status': 'Error 5001'})
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    key = dkey.getDkey()
    return jsonify({'key': key, 'status': 'OK'})


@app.route('/api/dkey/verify', methods=['get'])
@limiter.limit("6000/day;3000/hour;30/minute", error_message='超过限制')
def api_dkey_verify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return jsonify({'key': '000000', 'status': 'Error 5001'})
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    pwd = request.args['key']
    key = dkey.getDkey()
    if pwd == key:
        return jsonify({'status': True})
    else:
        return jsonify({'status': False})


@app.route('/api/user/add', methods=['POST'])
def api_user_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    uid = int(time.time()) + int(random.random() * 10000000)
    username = request.form['username']
    password = request.form['password']
    sex = request.form['sex']
    SQLclass = request.form['class']
    t_class = SQLclass
    number = request.form['number']
    college = request.form['cdt']
    direction = request.form['cdt']
    title = request.form['cdt']
    realname = request.form['realname']
    portrait = request.form['portrait']
    intro = request.form['intro']
    category = request.form['category']
    frequency = 0
    phone = request.form['phone']
    qq = request.form['qq']
    email = request.form['email']
    wechat = request.form['wechat']
    lock = request.form['lock']
    modify = request.form['modify']
    if len(username) < 6 or len(username) > 20 or main.database.base_database.api_userquery('username',
                                                                                            username) != False:
        return jsonify('用户名长度或已有相同用户名错误，注册失败'), 201
    if len(password) < 6 or len(password) > 20:
        return jsonify('密码错误，注册失败'), 201
    if len(t_class) < 1:
        return jsonify('班级错误，注册失败'), 201
    if len(number) < 1 or main.database.base_database.api_userquery('number', number) != False:
        return jsonify('学号工号错误，注册失败'), 201
    if len(college) < 1 or len(direction) < 1 or len(title) < 1:
        return jsonify('方向专业错误，注册失败'), 201
    if len(realname) < 1:
        return jsonify('真实姓名错误，注册失败'), 201
    if len(category) < 1:
        return jsonify('用户类别错误，注册失败'), 201
    if len(phone) < 11 or phone[0] != '1' or main.database.base_database.api_userquery('phone', phone) != False:
        return jsonify('手机号码校验失败，注册失败'), 201
    if len(qq) < 5:
        return jsonify('QQ长度错误，注册失败'), 201
    if len(email) < 5 or main.database.base_database.api_userquery('email', email) != False:
        return jsonify('Email错误，注册失败'), 201

    mdbaua = main.database.base_database.api_user_add(uid, username, password, sex, SQLclass, t_class, number, college,
                                                      direction, title, realname, portrait,
                                                      intro, category, frequency, phone, qq, email, wechat, lock,
                                                      modify)
    if mdbaua == True:
        mdbaua = '注册成功'
    return jsonify(mdbaua), 201


@app.route('/api/uesr/query', methods=['GET'])
def api_user_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    type = request.args['t']
    value = request.args['v']
    userinfo = main.database.base_database.api_userquery(type, value)
    return jsonify(userinfo), 201


@app.route('/api/student/uesr/query', methods=['GET'])
def api_student_user_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    type = request.args['t']
    value = request.args['v']
    userinfo = main.database.base_database.api_userNamequery(type, value)
    return jsonify(userinfo), 201


@app.route('/api/score/query', methods=['GET'])
def api_score_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    type = request.args['t']
    value = request.args['v']
    userinfo = main.database.base_database.api_topicquery(type, value)[0]
    score = main.database.base_database.api_scorequery('topic_id', userinfo[0])
    return jsonify(score, userinfo), 201


@app.route('/api/score/update', methods=['GET'])
def api_score_update():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    type = request.args['t']
    value = request.args['v']
    student_num = request.args['sn']
    userinfo = main.database.base_database.api_topicquery('t_snumber', student_num)[0]
    update_score = main.database.base_database.api_updateScore(userinfo[0], type, value)
    return jsonify(update_score), 201


@app.route('/api/uesr/query/dtt', methods=['GET'])
def api_user_query_dtt():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    json = {
        "result": 1,
        "message": "成功",
        "data": []
    }

    # 这个地方需要有一个验证jwt是否是管理员的东西
    type = request.args['t']
    value = request.args['v']
    userinfo = main.database.base_database.api_userquery(type, value)
    json["data"].append(userinfo)
    return json, 201


@app.route('/api/user/modify', methods=['POST'])
def api_user_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    id = request.form['id']
    username = request.form['username']
    password = request.form['password']
    sex = request.form['sex']
    SQLclass = request.form['SQLclass']
    t_class = request.form['t_class']
    number = request.form['number']
    college = request.form['college']
    direction = request.form['direction']
    title = request.form['title']
    realname = request.form['realname']
    portrait = request.form['portrait']
    intro = request.form['intro']
    category = request.form['category']
    frequency = request.form['frequency']
    phone = request.form['phone']
    qq = request.form['qq']
    email = request.form['email']
    wechat = request.form['wechat']
    lock = request.form['lock']

    mdbaum = main.database.base_database.api_usermodify(id, username, password, sex, SQLclass, t_class, number, college,
                                                        direction, title, realname, portrait,
                                                        intro, category, frequency, phone, qq, email, wechat, lock)
    return jsonify(mdbaum), 201


@app.route('/api/user/sendmail_r', methods=['POST'])
def api_user_sendmail():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    to = request.form['to']
    title = request.form['t']
    content = request.form['c']
    id = request.form['id']
    fpid = request.form['fpid']
    if title is None or content is None or id is None:
        return False
    main.database.base_database.admin_user_changePassword(id, '233333')
    main.database.base_database.admin_user_changePassword_updateStatus(fpid)
    mail = main.email.mailmain.SendMail(to, title, content)
    return jsonify(mail), 201


@app.route('/api/user/sendmail_p', methods=['POST'])
def api_user_sendmail_p():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    id = request.form['id']
    pwd = request.form['pwd']
    data = main.database.base_database.api_userquery('id', id)
    to = data[0][18]
    title = '毕业设计管理系统 -- 密码重置通知'
    content = '同学你好\n你的密码重置申请已经通过，新密码为：' + pwd + '\n如有疑问请联系教务处'
    mail = main.email.mailmain.SendMail(to, title, content)
    return jsonify(mail), 201


@app.route('/api/user/updateStatus', methods=['POST'])
def api_user_updateStatus():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    qaq = request.form['id']
    type = request.form['t']
    qwq = main.database.base_database.admin_user_changePassword_updateStatus(qaq, type)
    return jsonify(qwq), 201


@app.route('/api/user/passreset', methods=['POST'])
def api_user_passreset():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    id = request.form['idd']
    pwd = request.form['pwd']
    qwq = main.database.base_database.admin_user_changePassword(id, pwd)
    return render_template('admin/UserManage/PassSuccess.html')


@app.route('/api/user/messager/adminVerify', methods=['POST'])
@limiter.limit("30/day;5/hour;1/minute", error_message='短信验证码已发送，请一分钟后再试')
def api_user_messager_adminVerify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    # id = request.form['id']
    # print('qwq' + id)
    userinfo = main.database.base_database.api_userquery('id', id)[0]
    vc_random = int(random.random() * 1000000)
    message = main.message.mes.SendMessage(userinfo[16], 'SMS_206536350', str(vc_random))
    main.database.base_database.api_verifycode_insert(userInfoDict[1], vc_random, '1')
    print(userinfo)

    return jsonify(), 201


@app.route('/api/user/messager/verify', methods=['POST'])
@limiter.limit("100/day;30/hour;10/minute", error_message='短信验证码已发送，请一分钟后再试')
def api_user_messager_verify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    uid = request.form['uid']
    code = request.form['code']
    userinfo = main.database.base_database.api_userquery('uid', uid)[0]
    verify = main.database.base_database.api_verifycode_verify(userInfoDict[1], code)
    print(verify)
    return jsonify(verify), 201


@app.route('/api/user/upload/inputxls', methods=['POST'])
def api_user_upload_inputxls():
    path = 'upload/UploadUserInfo/' + request.form['path']
    qwq = main.document.user.addUserFromExcel(path)
    return jsonify(qwq), 201


@app.route('/api/notice/add', methods=['POST'])
def api_notice_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    title = request.form['title']
    user = request.form['user']
    text = request.form['text']
    qwq = main.database.base_database.api_notice_insert(title, user, text, userInfoDict[7])
    return jsonify(qwq), 201


@app.route('/api/notice/advice/add', methods=['POST'])
def api_notice_advice_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    title = request.form['title']
    text = request.form['text']
    type = request.form['type']
    u = request.form['u']
    ug = request.form['ug']
    qwq = 'False'
    if u == None or title == None or type == None:
        return jsonify(qwq), 201
    if type == '1':
        user = ug
        userGroupAll = main.database.base_database.CommonQuery('user', 'direction', user)
        for userGroupAll in userGroupAll:
            receInfo = main.database.base_database.api_userquery('uid', userGroupAll[1])
            qwq = main.database.base_database.api_advice_insert(userInfoDict[1], type, userGroupAll[1], title, text,
                                                                userInfoDict[11], receInfo[0][11])
    elif type == '0':
        user = u
        receInfo = main.database.base_database.api_userquery('uid', user)
        qwq = main.database.base_database.api_advice_insert(userInfoDict[1], type, user, title, text, userInfoDict[11],
                                                            receInfo[0][11])
    return jsonify(qwq), 201


@app.route('/api/notice/advice/reply', methods=['POST'])
def api_notice_advice_reply():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    aid = request.form['aid']
    adviceQuery = main.database.base_database.CommonQuery('advice', 'id', aid)[0]
    if adviceQuery[3] != userInfoDict[1]:
        return jsonify('不是本用户的通知不能回复'), 201
    reply = request.form['reply']

    qwq = main.database.base_database.api_updateAdviceReply(aid, reply)

    return jsonify(qwq), 201


@app.route('/api/notice/modify', methods=['POST'])
def api_notice_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    nid = request.form['nid']
    title = request.form['title']
    text = request.form['text']
    updateNotice = main.database.base_database.api_updateNotice(nid, title, text)
    return jsonify(updateNotice), 201


@app.route('/api/notice/delete', methods=['GET'])
def api_notice_delete():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    nid = request.args['nid']
    delete_notice = main.database.base_database.api_Deletenotice(nid)
    return jsonify(delete_notice), 201


@app.route('/api/notice/chat/getbyuser', methods=['POST'])
def api_notice_chat_getByUser():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    oid = request.form['oid']
    return jsonify(main.database.base_database.chatObjectAll(userInfoDict[1], oid)), 201


@app.route('/api/notice/chat/sendmessage', methods=['POST'])
def api_notice_chat_sendmessage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    uid = request.form['uid']
    oid = request.form['oid']
    text = request.form['text']
    if text == '':
        return jsonify('不能发送空白消息'), 201
    result = main.database.base_database.chatSendMessage(uid, oid, text, userInfoDict[11])
    return jsonify(result), 201


@app.route('/api/notice/chat/reback', methods=['POST'])
def api_notice_chat_reback():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return jsonify('鉴权错误，请重新登录'), 201
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    id = request.form['id']
    res = main.database.base_database.CommonQuery('chat', 'id', id)
    if id == '' or res == False:
        return jsonify('不能撤回空白消息'), 201
    if res[0][1] != uid:
        return jsonify('该消息不能撤回，不是本用户发送的'), 201
    if res[0][7] == 1:
        return jsonify('该消息不能撤回，原因是对方已读'), 201
    main.database.base_database.chatRebackUpdate(id)
    return jsonify('撤回成功'), 201


@app.route('/api/topic/add', methods=['POST'])
def api_topic_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    title = request.form['title']
    tea = request.form['tea']
    stu = request.form['stu']

    if title == '' or tea == '' or stu == '':
        return jsonify('请填写全部内容'), 201
    checked = main.database.base_database.CommonQuery('topic', 't_snumber', stu)
    if checked != False:
        return jsonify('该学生已经选过题目'), 201
    result = main.database.base_database.topic_add(title, tea, stu)
    return jsonify(result), 201


@app.route('/api/teacher/topic/add', methods=['POST'])
def api_teacher_topic_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    title = request.form['title']
    tea = userInfoDict[7]
    stu = request.form['stu']

    checked = main.database.base_database.CommonQuery('topic', 't_snumber', stu)
    if checked != False and stu != '-1':
        return jsonify('该学生已经选过题目'), 201
    result = main.database.base_database.topic_add(title, tea, stu)
    return jsonify(result), 201


@app.route('/api/topic/query', methods=['GET'])
def api_topic_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    type = request.args['t']
    value = request.args['v']
    userinfo = main.database.base_database.api_topicquery(type, value)
    return jsonify(userinfo), 201


@app.route('/api/topic/modify', methods=['POST'])
def api_topic_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    id = request.form['id']
    sn = request.form['t_snumber']
    title = request.form['title']
    tn = request.form['t_tnumber']
    mdbaum = main.database.base_database.api_topicmodify(id, sn, title, tn)
    return jsonify(mdbaum), 201


@app.route('/api/docs/manage', methods=['POST'])
def api_docs_manage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    u = request.form['u']
    d = request.form['d']
    if u != '-1':
        if u == '1':
            conb.setConfig('uploadpermission', '0')
        else:
            conb.setConfig('uploadpermission', '1')
        return jsonify(not u)
    if d != '-1':
        if d == '1':
            conb.setConfig('downloadpermission', '0')
        else:
            conb.setConfig('downloadpermission', '1')
        return jsonify(not d)


@app.route('/api/docs/return')
def api_docs_return():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return jsonify({'error': 'Signature Expired'})
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    num = request.args['num']
    student = main.database.base_database.api_userquery('number', num)[0]
    if student[14] != 3:
        return jsonify({'error': '所选用户不是学生'})
    if student[21] != '0':
        return jsonify({'error': '已被退回'})
    return_update = main.database.base_database.returned_update(num)
    if return_update == False:
        return jsonify({'error': '退回失败'})
    return jsonify({'error': '退回成功'})


@app.route('/api/docs/score', methods=['POST'])
def api_docs_score():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return jsonify({'error': 'Signature Expired'})
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    tid = request.form['tid']  # 论文ID
    kd = request.form['kd']  # 阶段
    score = request.form['score']  # 成绩

    if kd == '1':
        kd = 'op_score'
    elif kd == '2':
        kd = 'mi_score'
    elif kd == '3':
        kd = 'th_score'
    else:
        return jsonify({'error': '成绩录入失败，请通过 成绩管理->录入成绩 进行操作'})

    update_score = main.database.base_database.api_updateScore(tid, kd, score)
    if update_score == False:
        return jsonify({'error': '成绩录入失败，请通过 成绩管理->录入成绩 进行操作'})
    return jsonify({'error': '录入成功'})


@app.route('/api/login/manage', methods=['POST'])
def api_login_manage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    u = request.form['u']
    if u == '1':
        conb.setConfig('loginpermission', '0')
    else:
        conb.setConfig('loginpermission', '1')
    return jsonify(not u)


@app.route('/api/chat/manage', methods=['POST'])
def api_chat_manage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    u = request.form['u']
    if u == '1':
        conb.setConfig('chatpromission', '0')
    else:
        conb.setConfig('chatpromission', '1')
    return jsonify(not u)


@app.route('/api/message/manage', methods=['POST'])
def api_message_manage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    u = request.form['u']
    t = request.form['t']
    '''
    messagesignname = 花汐毕业设计管理系统
    accesskeyid = ZpmnHzpBtseL81DK
    accesssecret = MsWmzldDUPaSgggUUY1DSawRDlBm8N
    '''
    if t == '1':
        conb.setConfig('messagesignname', u)
    elif t == '2':
        conb.setConfig('accesskeyid', u)
    elif t == '3':
        conb.setConfig('accesssecret', u)
    return jsonify(not u)


@app.route('/api/mail/manage', methods=['POST'])
def api_mail_manage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    u = request.form['u']
    t = request.form['t']
    if t == '1':
        conb.setConfig('mailhost', u)
    elif t == '2':
        conb.setConfig('mailuser', u)
    elif t == '3':
        conb.setConfig('mailpass', u)
    elif t == '4':
        conb.setConfig('mailsender', u)
    return jsonify(not u)


@app.route('/api/defend/add', methods=['POST'])
def api_defend_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    title = request.form['title']
    time = request.form['time']
    content = request.form['c']
    user = request.form['u']
    add = main.database.base_database.defend_add(title, time, content, user)
    defend_query = main.database.base_database.CommonQuery('defend', 'title', title)[0]
    main.database.base_database.defend_score_add(defend_query[0], user)
    return jsonify(add), 201


@app.route('/api/defend/signin/change', methods=['POST'])
def api_defend_signin_change():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    id = request.form['id']
    flag = request.form['flag']
    verifyCode = request.form['vc']
    if not main.database.base_database.api_verifycode_verify(userInfoDict[1], verifyCode):
        return jsonify({"errno": 1004, "errmsg": "验证码不正确，详情参见帮助页面"}), 302
    status = main.database.base_database.api_defendSigninStatusChange(id, flag)
    return jsonify(status), 201


@app.route('/login/forget')
def login_forget():
    return render_template('forgot_password.html')


@app.route('/api/forget/submit', methods=['POST'])
def api_forget_submit():
    name = request.form['name']
    number = request.form['number']
    phone = request.form['phone']
    email = request.form['email']
    useragent = request.headers.get("User-Agent")

    submit_forg = main.database.base_database.insert_forget(name, number, phone, email, useragent)
    return jsonify(submit_forg)


@app.route('/admin')
def admin():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    notice = main.database.base_database.CommonQueryAll('notice where `display` = 1 order by id desc')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    thisStage = [conb.getConfigStr('thisStage'), conb.getConfigStr('thisStageTime')]
    return render_template('admin/index.html', userInfoDict=userInfoDict, thisStage=thisStage, notice=notice)


@app.route('/admin/profile')
def admin_profile():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/profile.html', userInfoDict=userInfoDict)


@app.route('/admin/user/add')
def admin_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    count = main.database.base_database.admin_user_query_count()
    return render_template('admin/UserManage/add.html', count=count, userInfoDict=userInfoDict)


@app.route('/admin/user/query')
def admin_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_userqueryAll()
    print(data)
    return render_template('admin/UserManage/query.html', data=data, userInfoDict=userInfoDict)


@app.route('/admin/user/query/result', methods=['GET'])
def admin_query_withid():
    qid = request.args['qid']
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    print('qwq', userInfoDict)
    data = main.database.base_database.api_userquery('id', qid)
    if data == False:
        return redirect('/admin/user/query')
    if data[0][14] == 3:
        topic = main.database.base_database.api_topicquery('t_snumber', data[0][7])
        if topic == False:
            return render_template('admin/UserManage/query_result.html', userInfoDict=userInfoDict, data=data[0],
                                   topic=[], teacher=[], paper=[], not_submit=1)
        teacher = main.database.base_database.api_userquery('number', topic[0][3])
        paper = main.database.base_database.api_paperquery('topic_id', topic[0][0])
        if paper == False:
            paper = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        return render_template('admin/UserManage/query_result.html', userInfoDict=userInfoDict, data=data[0],
                               topic=topic[0], teacher=teacher[0], paper=paper[0])
    return render_template('admin/UserManage/query_result.html', userInfoDict=userInfoDict, data=data[0])


@app.route('/admin/user/modify')
def admin_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/UserManage/modify.html', userInfoDict=userInfoDict)


@app.route('/admin/user/findpass')
def admin_user_findpass():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    undata = main.database.base_database.admin_user_findpass_api()
    data = main.database.base_database.admin_user_findpass_api(1)
    b_data = main.database.base_database.admin_user_findpass_api(2)
    count = main.database.base_database.admin_user_changePassword_CountAll()
    if undata == False:
        undata = []
    if data == False:
        data = []
    if b_data == False:
        b_data = []
    return render_template('admin/UserManage/findpass.html', undata=undata, data=data, b_data=b_data, count=count,
                           userInfoDict=userInfoDict)


@app.route('/admin/user/findpass/details', methods=['GET'])
def admin_user_findpass_details():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    id = request.args['id']
    fp_data = main.database.base_database.admin_user_findpassdetails_api(id)
    u_data = main.database.base_database.api_userquery('number', fp_data[2])
    if u_data == False:
        return render_template('error.html', error='未输入或未找到内容', errorHead='没有输入或未找到内容',
                               errorContent='请检查页面参数传递或联系管理员。'), 500
    if id == None or id == 0 or fp_data == False:
        return render_template('error.html', error='未输入或未找到内容', errorHead='没有输入或未找到内容',
                               errorContent='请检查页面参数传递或联系管理员。'), 500
    return render_template('admin/UserManage/findpass_details.html', fp_data=fp_data, u_data=u_data[0],
                           userInfoDict=userInfoDict)


@app.route('/admin/user/passreset?id=<id>')
def admin_user_passreset(id):
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    print(id)
    return render_template('admin/UserManage/passreset.html', idd=id, userInfoDict=userInfoDict)


@app.route('/admin/user/passreset')
def admin_user_passreset_noid():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    idd = -1
    return render_template('admin/UserManage/passreset.html', idd=idd, userInfoDict=userInfoDict)


@app.route('/admin/user/input?code=<code>')
def admin_user_input(code):
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    print(code)
    verify = main.database.base_database.api_verifycode_verify(userInfoDict[1], code)
    print(userInfoDict)
    print(verify)
    return render_template('admin/UserManage/input.html', verifyCode=verify, userinfo=userInfoDict,
                           userInfoDict=userInfoDict)


@app.route('/admin/user/input')
def admin_user_input_nocode():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/UserManage/input.html', userinfo=userInfoDict, userInfoDict=userInfoDict)


@app.route('/admin/score/insert')
def admin_score_insert():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/score/insert.html', userInfoDict=userInfoDict)


@app.route('/admin/score/query')
def admin_score_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_scorequeryAll()
    print(data)
    return render_template('admin/score/query.html', data=data, userInfoDict=userInfoDict)


@app.route('/admin/score/modify?code=<code>')
def admin_score_input(code):
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    verify = main.database.base_database.api_verifycode_verify(userInfoDict[1], code)
    return render_template('admin/score/modify.html', verifyCode=verify, userinfo=userInfoDict,
                           userInfoDict=userInfoDict)


@app.route('/admin/score/modify')
def admin_score_modify_nocode():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/score/modify.html', userinfo=userInfoDict, userInfoDict=userInfoDict)


@app.route('/admin/notice/add')
def admin_notice_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/notice/add.html', userinfo=userInfoDict, userInfoDict=userInfoDict)


@app.route('/admin/notice/list')
def admin_notice_list():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    list = main.database.base_database.CommonQueryAll('notice where `display` = 1')

    return render_template('admin/notice/list.html', list=list, userInfoDict=userInfoDict)


@app.route('/admin/notice/modify', methods=['GET'])
def admin_notice_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    nid = request.args['nid']
    request_article = main.database.base_database.CommonQuery('notice', 'id', nid)
    if request_article == False:
        return render_template('404.html')
    if request_article[0][7] == 0:
        return render_template('404.html')
    return render_template('admin/notice/notice_modify.html', request_article=request_article,
                           atc_text=request_article[0][2], userInfoDict=userInfoDict)


@app.route('/admin/notice/advice/add')
def admin_notice_advice_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    user = main.database.base_database.api_userqueryAll()
    user_group = main.database.base_database.api_userDirectionQueryAll()
    print(user_group)
    return render_template('admin/notice/advice/add.html', user=user, user_group=user_group, userInfoDict=userInfoDict)


@app.route('/admin/notice/advice/list')
def admin_notice_advice_list():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    myReceive = main.database.base_database.CommonQuery('advice', 'rece_num', uid)
    mySend = main.database.base_database.CommonQuery('advice', 'auth_num', uid)
    queryAll = main.database.base_database.CommonQueryAll('advice')
    return render_template('admin/notice/advice/list.html', myReceive=myReceive, mySend=mySend, queryAll=queryAll,
                           userInfoDict=userInfoDict)


@app.route('/admin/notice/chat')
def admin_notice_chat():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    user = main.database.base_database.api_userqueryAll()
    recentChatObject = main.database.base_database.recentChatObjectSelect(userInfoDict[1])
    if recentChatObject == False:
        recentChatObject = {}
    read = main.database.base_database.recentChatObjectSelectRead(userInfoDict[1])
    print(read)

    return render_template('admin/notice/chat/index.html', user=user, recentChatObject=recentChatObject,
                           RCO_keys=recentChatObject.keys(), userInfoDict=userInfoDict, read=read)


@app.route('/admin/topic/add')
def admin_topic_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    stu = main.database.base_database.api_userquery('category', '3')
    tea = main.database.base_database.api_userquery('category', '10')
    return render_template('admin/topic/add.html', stu=stu, tea=tea, userInfoDict=userInfoDict)


@app.route('/admin/topic/query')
def admin_topic_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    allTopic = main.database.base_database.topic_query()
    return render_template('admin/topic/query.html', allTopic=allTopic, userInfoDict=userInfoDict)


@app.route('/admin/topic/modify')
def admin_topic_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('admin/topic/modify.html', userInfoDict=userInfoDict)


@app.route('/admin/docs/open')
def admin_docs_open():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_docsQueryAll('open')
    return render_template('admin/docs/query.html', kaidan='开题', data=data, userInfoDict=userInfoDict)


@app.route('/admin/docs/middle')
def admin_docs_middle():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_docsQueryAll('middle')
    return render_template('admin/docs/query.html', kaidan='中期', data=data, userInfoDict=userInfoDict)


@app.route('/admin/docs/thesis')
def admin_docs_thesis():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_docsQueryAll('thesis')
    return render_template('admin/docs/query.html', kaidan='终稿', data=data, userInfoDict=userInfoDict)


@app.route('/admin/docs/manage')
def admin_docs_manage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    up = conb.getConfig('uploadpermission')
    dp = conb.getConfig('downloadpermission')
    return render_template('admin/docs/manage.html', up=up, dp=dp, userInfoDict=userInfoDict)


@app.route('/admin/defend/add')
def admin_defend_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    DUGSA = main.database.base_database.defendUserGroupSelectAll()
    return render_template('admin/defend/add.html', user_group=DUGSA, userInfoDict=userInfoDict)


@app.route('/admin/defend/query')
def admin_defend_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    # defend_info = main.database.base_database.CommonQueryAll('defend')
    defend_info = main.database.base_database.defendQueryPeopleNumber()
    return render_template('admin/defend/query.html', defend_info=defend_info, userInfoDict=userInfoDict)


@app.route('/admin/defend/query/result', methods=['GET'])
def admin_defend_query_result():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    defend_info = request.args['did']
    defend_info_arr = main.database.base_database.CommonQuery('defend', 'id', defend_info)
    defend_user_info = main.database.base_database.api_defendQueryResult(defend_info)
    return render_template('admin/defend/result.html', defend_info_arr=defend_info_arr,
                           defend_user_info=defend_user_info, userInfoDict=userInfoDict)


@app.route('/admin/settings/common')
def admin_settings_common():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    loginpromission = conb.getConfig('loginpermission')
    chatPromission = conb.getConfig('chatpromission')
    return render_template('admin/settings/common.html', userInfoDict=userInfoDict, loginpromission=loginpromission,
                           chatPromission=chatPromission)


@app.route('/admin/settings/message')
def admin_settings_message():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    messageSignName = conb.getConfigStr('messageSignName')
    accessKeyId = conb.getConfigStr('accessKeyId')
    accessSecret = conb.getConfigStr('accessSecret')
    return render_template('admin/settings/message.html', messageSignName=messageSignName, accessKeyId=accessKeyId,
                           accessSecret=accessSecret, userInfoDict=userInfoDict)


@app.route('/admin/settings/stage')
def admin_settings_stage():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    stage = conb.getConfigStr('thisStage')
    stageTime = conb.getConfigStr('thisStageTime')
    return render_template('admin/settings/stage.html', userInfoDict=userInfoDict, stage=stage, stageTime=stageTime)


@app.route('/admin/settings/mail')
def admin_settings_mail():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    mailhost = conb.getConfigStr('mailhost')
    mailuser = conb.getConfigStr('mailuser')
    mailpass = conb.getConfigStr('mailpass')
    mailsender = conb.getConfigStr('mailsender')
    return render_template('admin/settings/mail.html', userInfoDict=userInfoDict, mailhost=mailhost, mailuser=mailuser,
                           mailpass=mailpass, mailsender=mailsender)


@app.route('/teacher')
def teacher():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    notice = main.database.base_database.CommonQueryAll('notice where `display` = 1 order by id desc')
    thisStage = [conb.getConfigStr('thisStage'), conb.getConfigStr('thisStageTime')]
    myReceiveAdvice = main.database.base_database.CommonQuery('advice', 'rece_num', uid)
    mySendAdvice = main.database.base_database.CommonQuery('advice', 'auth_num', uid)
    return render_template('teacher/index.html', userInfoDict=userInfoDict, notice=notice, thisStage=thisStage,
                           myReceiveAdvice=myReceiveAdvice, mySendAdvice=mySendAdvice)


@app.route('/teacher/user/query')
def teacher_user_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.teacher_StudentQuery(userInfoDict[7])
    return render_template('teacher/UserManage/index.html', userInfoDict=userInfoDict, data=data)


@app.route('/teacher/user/profile')
def teacher_user_profile():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('teacher/UserManage/profile.html', userInfoDict=userInfoDict)


@app.route('/teacher/score/insert')
def teacher_score_insert():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('teacher/score/insert.html', userInfoDict=userInfoDict)


@app.route('/teacher/score/query')
def teacher_score_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_scorequeryAll()
    print(data)
    return render_template('teacher/score/query.html', data=data, userInfoDict=userInfoDict)


@app.route('/teacher/score/modify?code=<code>')
def teacher_score_input(code):
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    verify = False
    if code == dkey.getDkey():
        verify = True
    return render_template('teacher/score/modify.html', verifyCode=verify, userinfo=userInfoDict,
                           userInfoDict=userInfoDict)


@app.route('/teacher/score/modify')
def teacher_score_modify_nocode():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)

    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('teacher/score/modify.html', userinfo=userInfoDict, userInfoDict=userInfoDict)


@app.route('/teacher/notice/advice/add')
def teacher_notice_advice_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    user = main.database.base_database.api_userqueryAll()
    user_group = main.database.base_database.api_userDirectionQueryAll()
    print(user_group)
    return render_template('teacher/notice/advice/add.html', user=user, user_group=user_group,
                           userInfoDict=userInfoDict)


@app.route('/teacher/notice/advice/list')
def teacher_notice_advice_list():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    myReceive = main.database.base_database.CommonQuery('advice', 'rece_num', uid)
    mySend = main.database.base_database.CommonQuery('advice', 'auth_num', uid)
    return render_template('teacher/notice/advice/list.html', myReceive=myReceive, mySend=mySend,
                           userInfoDict=userInfoDict)


@app.route('/teacher/notice/chat')
def teacher_notice_chat():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    user = main.database.base_database.api_userqueryAll()
    recentChatObject = main.database.base_database.recentChatObjectSelect(userInfoDict[1])
    if recentChatObject == False:
        recentChatObject = {}
    read = main.database.base_database.recentChatObjectSelectRead(userInfoDict[1])
    print(read)

    return render_template('teacher/notice/chat/index.html', user=user, recentChatObject=recentChatObject,
                           RCO_keys=recentChatObject.keys(), userInfoDict=userInfoDict, read=read)


@app.route('/teacher/topic/add')
def teacher_topic_add():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    stu = main.database.base_database.api_userquery('category', '3')
    # tea = main.database.base_database.api_userquery('category', '10')
    return render_template('teacher/topic/add.html', stu=stu, userInfoDict=userInfoDict)


@app.route('/teacher/topic/query')
def teacher_topic_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    allTopic = main.database.base_database.topic_query()
    return render_template('teacher/topic/query.html', allTopic=allTopic, userInfoDict=userInfoDict)


@app.route('/teacher/topic/modify')
def teacher_topic_modify():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    datas = main.database.base_database.topic_query()
    return render_template('teacher/topic/modify.html', userInfoDict=userInfoDict, datas=datas)


@app.route('/teacher/docs/open')
def teacher_docs_open():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_docsQueryAll('open')
    return render_template('teacher/docs/query.html', kaidan='开题', data=data, userInfoDict=userInfoDict, kd=1)


@app.route('/teacher/docs/middle')
def teacher_docs_middle():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_docsQueryAll('middle')
    return render_template('teacher/docs/query.html', kaidan='中期', data=data, userInfoDict=userInfoDict, kd=2)


@app.route('/teacher/docs/thesis')
def teacher_docs_thesis():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    data = main.database.base_database.api_docsQueryAll('thesis')
    return render_template('teacher/docs/query.html', kaidan='终稿', data=data, userInfoDict=userInfoDict, kd=3)


@app.route('/teacher/defend/start')
def teacher_defend_start():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    # defend_info = main.database.base_database.CommonQueryAll('defend')
    defend_info = main.database.base_database.defendQueryPeopleNumber()
    return render_template('teacher/defend/start.html', defend_info=defend_info, userInfoDict=userInfoDict)


@app.route('/teacher/defend/start/result', methods=['GET'])
def teacher_defend_s_result():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    defend_info = request.args['did']
    defend_info_arr = main.database.base_database.CommonQuery('defend', 'id', defend_info)
    if defend_info_arr[0][5] != 1:
        return jsonify({'error': '答辩还未开始，不能进行签到操作'})
    defend_user_info = main.database.base_database.api_defendQueryResult(defend_info)
    return render_template('teacher/defend/s_result.html', defend_info_arr=defend_info_arr,
                           defend_user_info=defend_user_info, userInfoDict=userInfoDict)


@app.route('/teacher/defend/query')
def teacher_defend_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    # defend_info = main.database.base_database.CommonQueryAll('defend')
    defend_info = main.database.base_database.defendQueryPeopleNumber()
    return render_template('teacher/defend/query.html', defend_info=defend_info, userInfoDict=userInfoDict)


@app.route('/teacher/defend/query/result', methods=['GET'])
def teacher_defend_query_result():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    defend_info = request.args['did']
    defend_info_arr = main.database.base_database.CommonQuery('defend', 'id', defend_info)
    defend_user_info = main.database.base_database.api_defendQueryResult(defend_info)
    return render_template('teacher/defend/result.html', defend_info_arr=defend_info_arr,
                           defend_user_info=defend_user_info, userInfoDict=userInfoDict)


@app.route('/teacher/defend/signin/last')
def teacher_defend_signin_last():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    lastSignin = main.database.base_database.teacher_SelectSigninLastOne(uid)
    if lastSignin == False:
        return jsonify({'error': 'No column found'})
    return jsonify(lastSignin[0])


@app.route('/teacher/defend/score/update')
def teacher_defend_score_update():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    snumber = request.args['sn']
    score = request.args['score']
    ds_query = main.database.base_database.CommonQuery('defend_score', 'student_number', snumber)
    if ds_query == False:
        return jsonify({'error': '找不到学生信息'})
    if ds_query[0][5] != 1:
        return jsonify({'error': '学生未签到'})
    if ds_query[0][4] != 0:
        return jsonify({'error': '该学生分数已经存在，分数为：%s' % (ds_query[0][4])})
    score_update = main.database.base_database.defend_score_update(snumber, score)
    if score_update == False:
        return jsonify({'error': '成绩提交失败'})
    return jsonify({'error': '成绩提交成功'})


@app.route('/student')
def stu():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    notice = main.database.base_database.CommonQueryAll('notice where `display` = 1 order by id desc')
    thisStage = [conb.getConfigStr('thisStage'), conb.getConfigStr('thisStageTime')]
    myReceiveAdvice = main.database.base_database.CommonQuery('advice', 'rece_num', uid)
    mySendAdvice = main.database.base_database.CommonQuery('advice', 'auth_num', uid)
    return render_template('student/index.html', userInfoDict=userInfoDict, notice=notice, thisStage=thisStage,
                           myReceiveAdvice=myReceiveAdvice, mySendAdvice=mySendAdvice)


@app.route('/student/profile')
def student_profile():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return render_template('student/profile.html', userInfoDict=userInfoDict)


@app.route('/student/topic/choose')
def student_topic_choose():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    topic_list = main.database.base_database.choose_topicQuery()
    # 检查用户是否选过题
    topicStudentInfo = main.database.base_database.CommonQuery('topic', 't_snumber', userInfoDict[7])
    return render_template('student/topic/choose.html', userInfoDict=userInfoDict, topic_list=topic_list,
                           topicStudentInfo=topicStudentInfo)


@app.route('/student/topic/choose/confirm')
def student_topic_choose_confirm():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    choose_id = request.args['tid']
    # 检查选题是否存在
    topicInfo = main.database.base_database.CommonQuery('topic', 'id', choose_id)
    if topicInfo == False:
        return render_template('common/d_error.html', title='选题不存在', content='')
    # 检查是否被选择
    if topicInfo[0][1] != '-1':
        return render_template('common/d_error.html', title='该选题已经被选择', content='')
    # 检查用户是否选过题
    topicStudentInfo = main.database.base_database.CommonQuery('topic', 't_snumber', userInfoDict[7])

    if topicStudentInfo != False:
        return render_template('common/d_error.html', title='此学生已经选过题目', content='')

    update_topic = main.database.base_database.api_StudentChooseTopic(userInfoDict[7], choose_id)

    return render_template('common/d_error.html', title='选题成功', content='')


@app.route('/student/topic/query')
def student_topic_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    topicStudentInfo = main.database.base_database.CommonQuery('topic', 't_snumber', userInfoDict[7])
    if topicStudentInfo != False:
        teacherInfo = main.database.base_database.api_userquery('number', topicStudentInfo[0][3])[0]
        print(teacherInfo)
        return render_template('student/topic/query.html', userInfoDict=userInfoDict, topicStudentInfo=topicStudentInfo,
                               teacherInfo=teacherInfo)

    return render_template('student/topic/query.html', userInfoDict=userInfoDict, topicStudentInfo=topicStudentInfo)


@app.route('/student/docs/open')
def student_docs_open():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    datas = main.database.base_database.student_topicQuery(userInfoDict[7])
    if datas == False:
        return render_template('common/d_error.html', title='此用户还未选题', content='请先选择题目，再进行开题报告的上传')
    return render_template('student/docs/upload.html', userInfoDict=userInfoDict, datas=datas)


@app.route('/student/docs/middle')
def student_docs_middle():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    datas = main.database.base_database.student_topicQueryMiddle(userInfoDict[7])
    if datas == False:
        return render_template('common/d_error.html', title='此用户还未选题', content='请先选择题目，再进行开题报告的上传')
    if datas[0][6] == None:
        return render_template('common/d_error.html', title='开题报告还未打分，不能进行中期报告的上传', content='请先联系导师打分，再进行上传')
    return render_template('student/docs/upload_middle.html', userInfoDict=userInfoDict, datas=datas)


@app.route('/student/docs/thesis')
def student_docs_thesis():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    datas = main.database.base_database.student_topicQueryThesis(userInfoDict[7])
    if datas == False:
        return render_template('common/d_error.html', title='此用户还未选题', content='请先选择题目，再进行开题报告的上传')
    if datas[0][6] == None:
        return render_template('common/d_error.html', title='开题报告还未打分，不能进行中期报告的上传', content='请先联系导师打分，再进行上传')
    if datas[0][7] == None:
        return render_template('common/d_error.html', title='中期报告还未打分，不能进行终稿的上传', content='请先联系导师打分，再进行上传')
    return render_template('student/docs/upload_thesis.html', userInfoDict=userInfoDict, datas=datas)


@app.route('/student/defend/query')
def student_defend_query():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    datas = main.database.base_database.student_topicQueryThesis(userInfoDict[7])
    # 判断选题
    if datas == False:
        return render_template('common/d_error.html', title='此用户还未选题', content='')
    # 判断论文是否上传
    if datas[0][6] == None:
        return render_template('common/d_error.html', title='开题报告还未打分，不能进行答辩', content='')
    if datas[0][7] == None:
        return render_template('common/d_error.html', title='中期报告还未打分，不能进行答辩', content='')
    if datas[0][8] == None:
        return render_template('common/d_error.html', title='论文终稿还未打分，不能进行答辩', content='')
    # 在答辩用户表中查询用户存在
    defendInfo = main.database.base_database.CommonQuery('defend_score', 'student_number', userInfoDict[7])
    # defend_score里面是否有这个人
    if defendInfo == False:
        return render_template('common/d_error.html', title='未能在答辩用户中找到你，如有疑问请联系指导教师', content='')
    # 答辩信息查询
    defend = main.database.base_database.CommonQuery('defend', 'id', str(defendInfo[0][1]))
    if defend == False:
        return render_template('common/d_error.html', title='未能找到答辩信息，如有疑问请联系指导教师', content='')
    return render_template('student/defend/query.html', userInfoDict=userInfoDict, defend=defend, defendInfo=defendInfo)


@app.route('/student/score')
def student_score():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    datas = main.database.base_database.student_topicQueryThesis(userInfoDict[7])
    # 判断选题
    if datas == False:
        return render_template('common/d_error.html', title='此用户还未选题', content='')
    defendInfo = main.database.base_database.CommonQuery('defend_score', 'student_number', userInfoDict[7])
    return render_template('student/score.html', userInfoDict=userInfoDict, datas=datas, defendInfo=defendInfo)


@app.route('/student/notice')
def student_notice():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    myReceive = main.database.base_database.CommonQuery('advice', 'rece_num', uid)
    return render_template('student/notice.html', userInfoDict=userInfoDict, myReceive=myReceive)


@app.route('/student/notice/chat')
def student_notice_chat():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    user = main.database.base_database.api_userqueryAll()
    recentChatObject = main.database.base_database.recentChatObjectSelect(userInfoDict[1])
    if recentChatObject == False:
        recentChatObject = {}
    read = main.database.base_database.recentChatObjectSelectRead(userInfoDict[1])
    print(read)

    return render_template('student/chat.html', user=user, recentChatObject=recentChatObject,
                           RCO_keys=recentChatObject.keys(), userInfoDict=userInfoDict, read=read)


@app.route('/defend/login')
def defend_login():
    key = request.args['key']
    tuid = request.args['tuid']
    did = request.args['did']
    defend_query = main.database.base_database.CommonQuery('defend', 'id', did)
    if defend_query[0][5] != 1:
        return render_template('common/d_error.html', title='答辩签到还未开始', content='请稍后再试')
    if did == None:
        return render_template('common/d_error.html', title='找不到答辩信息', content='详情参见帮助页面或联系系统管理员')
    decode_key = main.login.base.AESDecode(key, 'TWlzYWtpTmV0d29y')
    # print(main.login.base.AESEncode(dkey.getDkey(), 'TWlzYWtpTmV0d29y'))
    if dkey.getPrivateDkey(tuid) != decode_key:
        return render_template('common/d_error.html', title='二维码过期', content='请重新扫描屏幕上的二维码进行签到')
    return render_template('student/defend/login.html', key=key, defend_id=did, tuid=tuid)


@app.route('/defend/loginVerify', methods=['POST'])
def defend_login_verify():
    un = request.form['un']
    pw = hashlib.md5(request.form['pw'].encode(encoding='UTF-8')).hexdigest()
    did = request.form['did']
    tuid = request.form['tuid']
    login_type = 0  # 登陆方式：0用户名 1邮箱 2手机号
    query_login_type = 'username'
    if len(un) == 11 and un[0] == '1':
        login_type = 2
        query_login_type = 'phone'
    elif '@' in un:
        login_type = 1
        query_login_type = 'email'
    else:
        login_type = 0
    # 这个地方应该连数据库查询了
    type = main.database.base_database.login(login_type, un, pw)
    if type == False:
        return render_template('common/d_error.html', title='用户不存在', content='详情参见帮助页面或联系系统管理员')
    if type == 3:  # 学生
        userInfo = main.database.base_database.api_userquery(query_login_type, un)[0]
        # 有没有被退回
        if userInfo[21] != '0':
            return render_template('common/d_error.html', title='学生状态为被退回，不能参加答辩', content='详情参见帮助页面或联系系统管理员')
        student_paper = main.database.base_database.topic_paper_unionQuerySN(userInfo[7])
        # 有没有论文
        if student_paper == False:
            return render_template('common/d_error.html', title='查询不到学生的论文信息，不能参加答辩', content='详情请联系系统管理员')
        # 成绩有没有
        if student_paper[0][15] == None or student_paper[0][16] == None or student_paper[0][17] == None:
            return render_template('common/d_error.html', title='成绩状态不正确', content='可能是没有打分，请教师通过系统查询学生分数')
        # 论文有没有上传
        if student_paper[0][9] == None:
            return render_template('common/d_error.html', title='开题报告没有上传', content='由于文档没有上传因此不能参加答辩')
        if student_paper[0][10] == None:
            return render_template('common/d_error.html', title='中期报告没有上传', content='由于文档没有上传因此不能参加答辩')
        if student_paper[0][11] == None:
            return render_template('common/d_error.html', title='论文终稿没有上传', content='由于文档没有上传因此不能参加答辩')
        # 已经有答辩成绩

        defendInfo = main.database.base_database.CommonQuery('defend_score', 'student_number', userInfo[7])
        if defendInfo == False:
            return render_template('common/d_error.html', title='此学生不在本次答辩名单中',
                                   content='学生姓名：' + userInfo[11] + '\n学号：' + userInfo[7])
        if defendInfo != False:
            if defendInfo[0][4] != 0:
                return render_template('common/d_error.html', title='此学生已经参加过答辩', content='')
            if defendInfo[0][1] != int(did):
                return render_template('common/d_error.html', title='此学生不在本次答辩名单中', content='')

        # setcookie部分
        response = make_response(redirect('/defend/signin'))
        response.set_cookie('token', main.login.base.JWTCreater("3", str(userInfo[1])))
        response.set_cookie('username', userInfo[2])
        response.set_cookie('uid', userInfo[1])
        response.set_cookie('id', str(userInfo[0]))
        response.set_cookie('tuid', tuid)
        return response
    elif type == 0:  # 不允许登陆
        return render_template('common/d_error.html', title='用户登录被禁止', content='详情参见帮助页面或联系系统管理员')
    elif type == -1:
        return render_template('common/d_error.html', title='用户名或密码不正确', content='请重新输入用户名密码')
    if type != 3:
        return render_template('common/d_error.html', title='签到功能限定学生使用', content='详情参见帮助页面或联系系统管理员')
    else:
        return render_template('common/d_error.html', title='未知错误', content='')


@app.route('/defend/signin')
def defend_signin():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return render_template('common/d_error.html', title='用户登录失败或未登陆', content='请重新扫描教师端二维码进行登陆')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    paper = main.database.base_database.topic_paper_unionQuerySN(userInfoDict[7])
    teacher_info = main.database.base_database.api_userquery('number', paper[0][3])[0]
    return render_template('student/defend/signin.html', userInfoDict=userInfoDict, paper=paper,
                           teacher_info=teacher_info)


@app.route('/defend/signin/response')
def defend_signin_response():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    tuid = request.cookies.get("tuid")

    code = request.args['code']
    if code != dkey.getPrivateDkey('2333331233'):
        return jsonify({'msg': '签到码不正确。'}), 201

    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return render_template('common/d_error.html', title='用户登录失败或未登陆', content='请重新扫描教师端二维码进行登陆')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    # teacher_info = main.database.base_database.api_userquery('uid',tuid)[0]
    useragency = request.headers.get("User-Agent")
    signin = main.database.base_database.defend_signin_insert(uid, tuid, useragency, userInfoDict[7])
    if signin == False:
        return render_template('common/d_error.html', title='签到失败', content='请重新签到或在教师端手动签到')
    return jsonify({'msg': '签到成功，请等待教师端数据加载'}), 201


@app.route('/defend/dkey/get')
def defend_dkey_get():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return 'Signature has expired'
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return main.login.base.AESEncode(dkey.getPrivateDkey(uid), 'TWlzYWtpTmV0d29y')


@app.route('/defend/signin/dkey/get')
def defend_signin_dkey_get():
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return 'Signature has expired'
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    return dkey.getPrivateDkey('2333331233')


@app.route('/notice/article', methods=['GET'])
def notice_article():
    id = request.args['id']
    uid = request.cookies.get("uid")
    print(uid)
    if uid == None:
        return jsonify('用户未登录，不能查看通知'), 404
    else:
        userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    request_article = main.database.base_database.CommonQuery('notice', 'id', id)
    if request_article[0][7] == 0:
        return render_template('404.html')
    if userInfoDict[14] == 3 and (request_article[0][6] == 3 or request_article[0][6] == 1):
        return jsonify('用户权限不足'), 404
    if userInfoDict[14] == 10 and request_article[0][6] == 3:
        return jsonify('用户权限不足'), 404

    main.database.base_database.api_updateNoticeRead(id)
    return render_template('common/notice_article.html', request_article=request_article,
                           atc_text=request_article[0][2])


@app.route('/notice/advice/article', methods=['GET'])
def notice_advice_article():
    id = request.args['aid']
    uid = request.cookies.get("uid")
    print(uid)
    if uid == None:
        return jsonify('用户未登录，不能查看通知'), 404
    else:
        userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]
    request_article = main.database.base_database.CommonQuery('advice', 'id', id)
    if request_article == False:
        return render_template('404.html')
    if request_article[0][7] == 0:
        return render_template('404.html')
    if userInfoDict[14] == 3 and request_article[0][3] != userInfoDict[1]:
        return jsonify('你所访问的通知不存在或不是本人通知。'), 404
    if userInfoDict[14] == 10 and request_article[0][6] == 3:
        return jsonify('用户权限不足'), 404

    main.database.base_database.api_updateNoticeRead(id)
    return render_template('common/advice_article.html', request_article=request_article,
                           atc_text=request_article[0][5], userInfoDict=userInfoDict)


# 文件相关

ALLOWED_EXTENSIONS = set(['doc', 'docx', 'xlsx', 'xls', 'pdf', 'jpg', 'png'])  # 允许上传的文件后缀


# 判断文件是否合法
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


# 具有上传功能的页面
@app.route('/test/upload')
def upload_test():
    return render_template('common/upload.html')


@app.route('/api/upload', methods=['POST'], strict_slashes=False)
def api_upload():
    if conb.getConfig('uploadpermission') == 0:
        return jsonify({"errno": 2001, "errmsg": "上传失败，原因是管理员关闭了上传功能。详情请访问帮助页面。"}), 404
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(1, token, id, uid, username)
    if jwt_verify != True:
        jwt_verify = main.login.base.JWTVerify(10, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    topic_id = request.form['tid']
    type = request.form['t']
    topic_query = main.database.base_database.CommonQuery('paper', 'topic_id', topic_id)
    if topic_query == False:
        return jsonify({"errno": 2002, "errmsg": "未找到对应论文项目。详情请访问帮助页面。"})
    if type == '1':
        flo = 'open'
        UPLOAD_FOLDER = 'upload' + "/" + flo
    elif type == '2':
        flo = 'middle'
        UPLOAD_FOLDER = 'upload' + "/" + flo
    elif type == '3':
        flo = 'thesis'
        UPLOAD_FOLDER = 'upload' + "/" + flo
    else:
        return jsonify({"errno": 2003, "errmsg": "类型参数错误"})

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # 设置文件上传的目标文件夹
    basedir = os.path.abspath(os.path.dirname(__file__))  # 获取当前项目的绝对路径

    file_dir = os.path.join(basedir, app.config['UPLOAD_FOLDER'])  # 拼接成合法文件夹地址
    if not os.path.exists(file_dir):
        os.makedirs(file_dir)  # 文件夹不存在就创建
    f = request.files['myfile']  # 从表单的file字段获取文件，myfile为该表单的name值
    if f and allowed_file(f.filename):  # 判断是否是允许上传的文件类型
        fname = f.filename
        ext = fname.rsplit('.', 1)[1]  # 获取文件后缀
        unix_time = int(time.time())
        new_filename = str(userInfoDict[7]) + "_" + str(unix_time) + str(
            int(random.random() * 1000000)) + '.' + ext  # 修改文件名
        f.save(os.path.join(file_dir, new_filename))  # 保存文件到upload目录
        print(topic_id, flo + "/" + new_filename)
        qwq = main.database.base_database.api_UpdatePaperUpload(topic_id, type, flo + "/" + new_filename)

        return jsonify({"errno": 0, "errmsg": "上传成功"})
    else:
        return jsonify({"errno": 2004, "errmsg": "上传失败"})


@app.route('/api/student/upload', methods=['POST'], strict_slashes=False)
def api_student_upload():
    if conb.getConfig('uploadpermission') == 0:
        return jsonify({"errno": 2001, "errmsg": "上传失败，原因是管理员关闭了上传功能。详情请访问帮助页面。"}), 404
    token = request.cookies.get("token")
    id = request.cookies.get("id")
    uid = request.cookies.get("uid")
    username = request.cookies.get("username")
    jwt_verify = main.login.base.JWTVerify(3, token, id, uid, username)
    if jwt_verify != True:
        return redirect('/')
    userInfoDict = main.database.base_database.api_userquery('uid', uid)[0]

    topic_id = request.form['tid']
    type = request.form['t']
    topic_query = main.database.base_database.CommonQuery('paper', 'topic_id', topic_id)
    if topic_query == False:
        return jsonify({"errno": 2002, "errmsg": "未找到对应论文项目。详情请访问帮助页面。"})
    topic_info_query = main.database.base_database.CommonQuery('topic', 'id', topic_id)
    if topic_query == False:
        return jsonify({"errno": 2002, "errmsg": "未找到对应论文项目。详情请访问帮助页面。"})
    if topic_info_query[0][1] != userInfoDict[7]:
        return jsonify({"errno": 2009, "errmsg": "上传失败。"})
    if type == '1':
        flo = 'open'
        UPLOAD_FOLDER = 'upload' + "/" + flo
    elif type == '2':
        flo = 'middle'
        UPLOAD_FOLDER = 'upload' + "/" + flo
    elif type == '3':
        flo = 'thesis'
        UPLOAD_FOLDER = 'upload' + "/" + flo
    else:
        return jsonify({"errno": 2003, "errmsg": "类型参数错误"})

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # 设置文件上传的目标文件夹
    basedir = os.path.abspath(os.path.dirname(__file__))  # 获取当前项目的绝对路径

    file_dir = os.path.join(basedir, app.config['UPLOAD_FOLDER'])  # 拼接成合法文件夹地址
    if not os.path.exists(file_dir):
        os.makedirs(file_dir)  # 文件夹不存在就创建
    f = request.files['myfile']  # 从表单的file字段获取文件，myfile为该表单的name值
    if f and allowed_file(f.filename):  # 判断是否是允许上传的文件类型
        fname = f.filename
        ext = fname.rsplit('.', 1)[1]  # 获取文件后缀
        unix_time = int(time.time())
        new_filename = str(userInfoDict[7]) + "_" + str(unix_time) + str(
            int(random.random() * 1000000)) + '.' + ext  # 修改文件名
        f.save(os.path.join(file_dir, new_filename))  # 保存文件到upload目录
        print(topic_id, flo + "/" + new_filename)
        qwq = main.database.base_database.api_UpdatePaperUpload(topic_id, type, flo + "/" + new_filename)
        returned_set0 = main.database.base_database.returned_set0(userInfoDict[7])
        return jsonify({"errno": 0, "errmsg": "上传成功"})
    else:
        return jsonify({"errno": 2004, "errmsg": "上传失败"})


# 下载文件 例子（http://127.0.0.1:5000/download/）UploadUserInfo/1.xlsx
@app.route("/download/<path:filename>")
def downloader(filename):
    if conb.getConfig('downloadpermission') == 0:
        return jsonify({"errno": 3099, "errmsg": "下载失败"}), 404
    # filename = base64.b64decode(filename).decode("utf-8")
    dirpath = os.path.join(app.root_path, 'upload')  # 这里是下在目录，从工程的根目录写起，比如你要下载static/js里面的js文件，这里就要写“static/js”
    return send_from_directory(dirpath, filename, as_attachment=True)  # as_attachment=True 一定要写，不然会变成打开，而不是下载


@app.route('/faq_prev')
def faq_prev():
    return render_template('common/faq.html')

@app.route('/faq')
def faq():
    return render_template('common/faq/index.html')

@app.route('/faq/login')
def faq_login():
    return render_template('common/faq/login.html')

@app.route('/faq/file')
def faq_file():
    return render_template('common/faq/file.html')

@app.route('/faq/message')
def faq_message():
    return render_template('common/faq/message.html')

@app.route('/faq/info')
def faq_info():
    return render_template('common/faq/info.html')

@app.route('/faq/notice')
def faq_notice():
    return render_template('common/faq/notice.html')

@app.route('/versions')
def versions():
    return render_template('common/versions.html')

@app.route('/logout')
def logout():
    res = make_response(redirect('/'))
    res.delete_cookie('token')
    res.delete_cookie('id')
    res.delete_cookie('uid')
    res.delete_cookie('username')
    return res


@app.errorhandler(400)
def TooBadReq(error):
    errorHead = '400 BadRequest -- 这是一个错误的访问方式 请返回前一页面'
    errorContent = '请联系系统管理员'
    return render_template('error.html',
                           error='400 The browser (or proxy) sent a request that this server could not understand.',
                           errorHead=errorHead,
                           errorContent=errorContent), 400


@app.errorhandler(404)
def NotFound(error):
    errorHead = '404 Not Found -- 找不到这个页面呢'
    errorContent = '是不是网址输入错误了呢？'
    return render_template('404.html', error='404 找不到页面', errorHead=errorHead, errorContent=errorContent), 404


@app.errorhandler(405)
def MethodNotAllowed(error):
    errorHead = '405 Method Not Allowed -- 调用方法不被允许'
    errorContent = '请联系系统管理员'
    return render_template('error.html', error='405 Method Not Allowed', errorHead=errorHead,
                           errorContent=errorContent), 405


@app.errorhandler(429)
def TooManyRequests(error):
    errorHead = '429 Too Many Requests -- 过多请求'
    errorContent = '一段时间内访问次数过多，请稍后再试'
    return render_template('error.html', error='过多的请求', errorHead=errorHead, errorContent=errorContent), 429


if __name__ == '__main__':
    app.run()
