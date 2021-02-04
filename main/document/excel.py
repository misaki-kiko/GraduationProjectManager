import xlrd


def queryExcel(path):
    # 打开文件
    workbook = xlrd.open_workbook(path)
    # 根据sheet索引或者名称获取sheet内容
    sheet1 = workbook.sheet_by_index(0)  # sheet索引从0开始
    json = []
    for i in range(0, sheet1.nrows):
        json.append(sheet1.row_values(i))
    return json

