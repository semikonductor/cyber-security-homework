# 因为不同密文消息长度不同，所以需要一位一位的异或，比较麻烦
MSGS = [
    0x9b40d24ea114785f149fe7e442b5a6146c007a2daf445b6f51c9c8d15668aaba465267ab4d6392253bef29399008bb08e870122ddc4a0fc43347a95c73948af4fcd730,
    0xb8569b43a75a105810def6aa49acac0d6c49673aaf59402a1085c6dc4b6df8b6081731b95775893462ae683e9a18fa11e8345421d7066dc23540a65d66c0a8fef9dc,
    0xac5ccd49a219011355d2f3e14eb0e30f6b496635fd494d3d108fc0cc1979f9ef5c5431a35a758f712db67b758b0ebb1fe5714037920323812a48b2417bda,
    0xa05dde00b25d5d4f55cff3ee0baab0466f0c7c32ea4e5c2349c9dcdb5a79f8aa081731b75065db3223ad293b9a1dbf0ead764021d3016dc82e0da45d63da,
    0x8c5fda55a251106f19c8fde54fe3900e7e07603be10d413c1082c1d14e62aaae5b1b70ee1d769a252aa67b75900dfa15e3725d36df0b39c83543e0467cd1a6eeec9b71,
    0x885cd447aa511043069ffde44ee3ac003f1d6631af59473f10a8c2db4b65e9ae461b7cbb5364923f23b7603a910ab65cf971512cdc0521ce3d54e0517bd9b9fdfbd03410,
    0x9b52c24ca946107902d6f4fe0baab04670076b74e04b083b588c8fdc5c7ffeef5b5e7da2567e9c712fb67a3c9c02bb12fe345d22920b21cd7a59a95f71,
    0x8c5cd650b340555855ccf1e34eada0033f007d74fb454d6f439ddada402ce5a908587ea34f658f3036aa663bd34bbb09f97b5f25c60322cf760da15c7094a0f2f3d6230e53ad3142d9,
    0xad5ad749a45d5c4355d6e1aa4ae3b50f7b0c6174fc45493d5987c89e4e69e8bc414f74ee5d71883426e3603bdf38b21de3735a25db4a61813359e04575c7e9f9e6cd30015eb02b4597d69832af157d07ace558,
    0x9652d400b155430a06dafeef48b7a6023f0b7774fb454d6f6286ccd55c78f9ef494831ba5775db372bb17a21df04ac19ff755e28921a24c2310da95c34c0a1f9b58b615300

]
target = 0xb85bde4ee64143431bd8b2eb0bb0b7147a086374ec445827559b839e5769fcaa5a1b64bd5a308f3927e36230864bb713ff711230da0b23813543a357


# 将目标字符串每一位都取出来
def getBytes(sourceObj):
    ansArray = []
    while sourceObj > 0:
        endnum = int(sourceObj % 256)
        sourceObj //= 256
        ansArray.append(endnum)
    ansArray.reverse()
    return ansArray


# main函数
if __name__ == '__main__':
    # 将要解密的密文每一位都取出来
    targetStr = getBytes(target)
    # 将每一个密文的每一位都取出来
    for i in MSGS:
        massage = getBytes(i)
        # 异或每一位
        cx = 0  # 循环次数flag
        while cx < len(targetStr):
            out = targetStr[cx] ^ massage[cx]
            # 如果可以显示，则打印，否则输出问号->防止乱码
            if 127 > out > 31:
                print(chr(out), end="")
            else:
                print("?", end="")
            cx += 1
        print()
print("end")
