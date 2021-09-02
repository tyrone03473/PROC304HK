# test function
def check_value(src, dst, srcList, dstList, valueList):
    flag = 0
    for index, value in enumerate(srcList):
        if src == value:
            if dst == dstList[index]:
                valueList[index] += 1
                flag = 1
                break
        elif dst == value:
            if src == dstList[index]:
                valueList[index] += 1
                flag = 1
                break
    if flag == 0:
        srcList.append(src)
        dstList.append(dst)
        valueList.append(1)
    return srcList, dstList, valueList
srcList = [1,1]
dstList = [2,3]
valueList = [1,1]
srcList, dstList, valueList = check_value(3, 3, srcList, dstList, valueList)
print(valueList)