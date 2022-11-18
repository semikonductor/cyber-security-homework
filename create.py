from Crypto import Random
import time

MSGS = ['Tsing Hua university is a good university, located in Beijing China',
        'we can read books in the library , where makes me feel comfortable',
        'covid-19 makes it harder for us to meet our teachers in person',
        'one time pad is perfectly secure , you can never break it down',
        'Claude Elwood Shannon is known as a "father of information theory" ',
        'Google is one of the top American multinational technology companies',
        'Taylor Swift is one of the best selling musicians of all time',
        'Computer science is the study of computation, automation, and information',
        'bilibili is a video sharing website based in Shanghai , it was establish by chenrui',
        'Yao was selected by the Rockets as the first overall pick in the 2002',
        'when using a stream cipher, never use the key more than once'
        ]


# 将十六进制的数每两位分割开来
def getBytes(sourceObj):
    ansArray = []
    while sourceObj > 0:
        endnum = int(sourceObj % 256)
        sourceObj //= 256
        ansArray.append(endnum)
    ansArray.reverse()
    return ansArray


# 获取明文最大长度，以便生成足够长的key
def get_max_length(msgs):
    max_length = 0
    for i in msgs:
        if len(i) > max_length:
            max_length = len(i)
    return max_length


# 明文与key进行异或加密
def xor_process(msgs, key):
    cipher = []
    message = getBytes(int(msgs.encode("ascii").hex(), 16))
    key_bytes = getBytes(int(key, 16))
    cx = 0
    while cx < len(message):
        ans = message[cx] ^ key_bytes[cx]
        cipher.append(ans)
        cx += 1
    return cipher


# 调用库函数获得key
def get_key(length):
    key = Random.get_random_bytes(length)
    return key


# 将key储存在文件中
def write_key(key):
    with open('key.txt', 'w') as file:
        file.write(key + '\n')
        file.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))


# 将密文储存在文件中
def write_cipher(cipher):
    with open("cipher.txt", 'a') as file:
        file.write(cipher + '\n')


# main函数
if __name__ == "__main__":
    length = get_max_length(MSGS)
    key = get_key(length).hex()
    write_key(key)
    for i in MSGS:
        cipher = xor_process(i, key)
        sum = 0
        for j in cipher:
            sum = sum * 256 + j
        write_cipher(hex(sum))
    with open("cipher.txt", 'a') as file:
        file.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n')
