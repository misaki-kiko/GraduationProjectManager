import configparser

def getConfig(key):
    config = configparser.ConfigParser()
    config = configparser.ConfigParser(interpolation=configparser.BasicInterpolation())
    config.read("cfg.ini")
    return int(config['127.0.0.1:5000'][key])

def getConfigStr(key):
    config = configparser.ConfigParser()
    config = configparser.ConfigParser(interpolation=configparser.BasicInterpolation())
    config.read("cfg.ini")
    return str(config['127.0.0.1:5000'][key])

def setConfig(key, value):
    config = configparser.ConfigParser()
    config = configparser.ConfigParser(interpolation=configparser.BasicInterpolation())
    config.read("cfg.ini")
    qwq = config.set('127.0.0.1:5000', key, value)
    config.write(open('cfg.ini', "r+"))
    return True

# print(getConfig('uploadPermission'))