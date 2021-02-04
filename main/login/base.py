import jwt
import time
import base64
import hashlib
import main.database.base_database

from Crypto.Cipher import \
    AES  # 注：python3 安装 Crypto 是 pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple pycryptodome<br><br>

# 加密算法
PrivateKey = 'MisakiNetworkContributionPrivateKey'  # 默认通用私钥


# AES解密
def AESDecode(data, key):
    decrypted_text1 = ''
    try:
        aes = AES.new(str.encode(key), AES.MODE_ECB)  # 初始化加密器
        decrypted_text1 = aes.decrypt(base64.decodebytes(bytes(data, encoding='utf8'))).decode("utf8")  # 解密
        decrypted_text1 = decrypted_text1[:-ord(decrypted_text1[-1])]  # 去除多余补位
    except Exception as e:
        pass
    return decrypted_text1


# AES加密
def AESEncode(data, key):
    while len(data) % 16 != 0:  # 补足字符串长度为16的倍数
        data += (16 - len(data) % 16) * chr(16 - len(data) % 16)
    data = str.encode(data)
    aes = AES.new(str.encode(key), AES.MODE_ECB)  # 初始化加密器
    return str(base64.encodebytes(aes.encrypt(data)), encoding='utf8').replace('\n', '')  # 加密


# 用户信息加密

# 普通用户
def NormalUserInfoEncode(id, uid, username):
    UserInfo = str(id) + '/' + str(uid) + '/' + username + '/' + PrivateKey
    Base64UserInfo = UserInfo.encode('utf-8')
    StrBase64UserInfo = str(base64.b64encode(Base64UserInfo), encoding='ascii')
    return StrBase64UserInfo


# 管理员
def AdminUserInfoEncode(id, uid, username):
    UserInfo = str(id) + '/' + str(uid) + '/' + username + '/' + PrivateKey
    Base64UserInfo = UserInfo.encode('utf-8')
    StrBase64UserInfo = str(base64.b64encode(Base64UserInfo), encoding='ascii')
    AESUserInfo = AESEncode(StrBase64UserInfo, 'TWlzYWtpTmV0d29y')
    ##未实现功能：AES密钥从数据库提取
    return AESUserInfo


# 用户信息提取

# 普通用户信息提取
def GetNormalUserInfo(type, username):
    UserArray = main.database.base_database.api_userquery(type, username)[0]
    if UserArray[14] == '99':
        return False
    return UserArray



# 管理员信息提取
def GetAdminUserInfo(type, username):
    UserArray = main.database.base_database.api_userquery(type, username)[0]
    if UserArray[14] != 99:
        return False
    return UserArray



# 用户信息字典生成
def CreateUserInfoDict(id, uid, UserName, UserType):
    UserInfoDict = {
        'id': id,
        'uid': uid,
        'un': UserName,
        'iat': int(time.time()),
        'exp': int(time.time() + 3600),
        'ut' : UserType
    }
    return UserInfoDict


# JWT实现

# JWT生成
def JWTCreater(UserType, uid):
    if UserType == '1':
        UserInfoDict = GetAdminUserInfo('uid', uid)
        if UserInfoDict == False:
            return False
        JWTEncoded = jwt.encode(CreateUserInfoDict(UserInfoDict[0], UserInfoDict[1], UserInfoDict[2],UserInfoDict[14]),
                                AdminUserInfoEncode(UserInfoDict[0], UserInfoDict[1], UserInfoDict[2]),
                                algorithm='HS256')
    else:
        UserInfoDict = GetNormalUserInfo('uid', uid)
        if UserInfoDict == False:
            return False
        JWTEncoded = jwt.encode(CreateUserInfoDict(UserInfoDict[0], UserInfoDict[1], UserInfoDict[2],UserInfoDict[14]),
                                NormalUserInfoEncode(UserInfoDict[0], UserInfoDict[1], UserInfoDict[2]),
                                algorithm='HS256')
    JWTEndodedString = str(JWTEncoded, encoding='ascii')
    return JWTEndodedString



# JWT验证
def JWTVerify(UserType, token, id, uid, UserName):
    if UserType == None or token == None or id == None or uid == None or UserName == None:
        return False
    print(UserType, token, id, uid, UserName)
    try:
        if UserType == 1:
            data = jwt.decode(str(token), str(AdminUserInfoEncode(id, uid, UserName)), algorithm='HS256')
        elif UserType == 10:
            data = jwt.decode(str(token), str(NormalUserInfoEncode(id, uid, UserName)), algorithm='HS256')
            if data['ut'] != 10:
                return False
        else:
            data = jwt.decode(str(token), str(NormalUserInfoEncode(id, uid, UserName)), algorithm='HS256')
            if data['ut'] != 3:
                return False
    except Exception as e:
        print(e)
        return False
    return True

# 用户信息验证

# 普通用户登陆验证
def NormalUserLoginVerify(username, password):
    UserArray = main.database.base_database.api_userquery('username', username)
    if UserArray[3] == password:
        Token = JWTCreater(UserArray[4], UserArray[2], UserArray[1])
        return Token
    else:
        return False


# 管理员用户登陆验证
def AdminUserLoginVerify(username, password):
    UserArray = main.database.base_database.api_userquery('username', username)
    if UserArray[3] == password:
        Token = JWTCreater(UserArray[4], UserArray[2], UserArray[1])
        return Token
    else:
        return False


# Token验证
def TokenVerify():
    return 0

# print(JWTCreater(10,'1618545044'))
# token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidWlkIjoiMTYwOTM2MjM5MSIsInVuIjoia2lrbyIsImlhdCI6MTYwNzMyMTk3OSwiZXhwIjoxNjA3MzI1NTc5LCJ1dCI6MH0.ZavwnzXRRNQbkDBzTHNgKRIaxpEQ3i4RrzsrWBPIIsw'
# print(JWTVerify(1, token, '1', '11609362391', 'kiko'))
