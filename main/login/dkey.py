import hmac
import datetime
import time

def getDkey():
    # 获取当前时间(时间戳)
    now_time = time.time()

    # 时间戳转时钟格式
    local_time = datetime.datetime.fromtimestamp(now_time)

    # print(local_time)

    # 校验一下输出时间的字符串位数
    # print(len(str(local_time)))

    # 截取前16位，截取到分
    time_min = str(local_time)[0:16]
    # print(time_min)

    # K 共享密钥（令牌种子）
    k = "3132333435363738393031323338632637383930" \
        "3132333435363738393031323323253637383930" \
        "3132333435363738393031323334353637319203" \
        "31323334"

    # string->bytes
    b_k = bytes(k, encoding='utf-8')
    b_m = bytes(str(time_min), encoding='utf-8')

    # 调HMAC生成随机口令

    # 加密算法
    digestmod = "MD5"
    h = hmac.new(b_k, b_m, digestmod)
    # print(h.hexdigest())

    # 将返回的16进制摘要截取6位
    hex_final = str(h.hexdigest())[0:6]

    # print(hex_final)

    # 转为10进制
    final = str(int(hex_final.upper(), 16))[0:6]
    # print(final)
    return final

def getPrivateDkey(uid):
    if len(uid) != 10:
        return False
    # 获取当前时间(时间戳)
    now_time = time.time()

    # 时间戳转时钟格式
    local_time = datetime.datetime.fromtimestamp(now_time)

    # print(local_time)

    # 校验一下输出时间的字符串位数
    # print(len(str(local_time)))

    # 截取前16位，截取到分
    time_min = str(local_time)[0:16]
    # print(time_min)

    # K 共享密钥（令牌种子）
    k = "3132333435363738393031323338632637383930" \
        "3132333435363738393031323323253637383930" \
        "31323334353637383930313233343536373192"+ str(uid)

    # string->bytes
    b_k = bytes(k, encoding='utf-8')
    b_m = bytes(str(time_min), encoding='utf-8')

    # 调HMAC生成随机口令

    # 加密算法
    digestmod = "MD5"
    h = hmac.new(b_k, b_m, digestmod)
    # print(h.hexdigest())

    # 将返回的16进制摘要截取6位
    hex_final = str(h.hexdigest())[0:6]

    # print(hex_final)

    # 转为10进制
    final = str(int(hex_final.upper(), 16))[0:6]
    # print(final)
    return final

# print(getPrivateDkey("1618545044"))