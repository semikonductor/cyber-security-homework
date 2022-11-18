---
author: semiconductor
---



# 多次密码本的安全性分析



[TOC]

## 背景介绍

### 一次性密码本 (One Time Pad)

​		流加密(stream cipher)又称串流加密，资料流加密，是一种对称加密。而其中最具有代表性的，理论上符合完美安全（prefect security）的就是一次性密码本(One Time Pad)。

​		但是一次性密码本也有自己的缺点：
1. 传递密文前，需要安全的传递一个与明文等长的密钥。如果有方法安全传递密钥，也就无需加密，直接使用相同的方法传递明文即可。
2. 每次加密都需要使用一个完全随机的新密钥。

​		由于以上的缺点，导致一次性密码本在现实中使用频率较少。并且由于人们对一次性密码本的了解缺失，产生了许多错误使用案例，导致了不安全的加密。本篇实验报告根据历史上著名的维诺那计划（Venona project），分析了多次使用同一密钥导致的不安全一次性密码本加密。

### 维诺那计划（Venona project）

​		1941-1946年，苏联使用一次性密码本加密消息 ，密码本的生成由人工丢骰子生成。本来天衣无缝的加密项目，却因为苏联密码制造部门业务量激增，为了赶得上进度而不得不偷懒复制了一部分一次性密码本。最后被美国破解，在美国称为Venona计划。

​		美国国家安全局报告说根据维诺那计划所显示的电报索引，苏联方面发送过几千条信息，但是只有一部分被破译。大概有2200条信息被成功破译并且被翻译出来；大概50%的驻华盛顿的格鲁乌-海军（GRU-Naval Washington）和莫斯科的通信消息被破译。但是其他的年份则没有这么好的运气，虽然在1941年至1945年间有数千条消息被发送。NKVD电报被破译的比率如下：

- 1942年：1.8%
- 1943年：15.0%
- 1944年：49.0%
- 1945年：1.5%

​		在这些成成千上万的被加密的通信信息中间，大概只有不超过3000条消息被部分或者全部破译出来。所有重复使用的一次性密码本都是在1942年被制造出来的，在1945年底之前，他们全部被使用了一遍，直到1948年这些密码仍然被小范围的使用过。在这之后，苏联方面彻底更换了密码系统，变得不可破解。

## 攻击原理

1. 假设获取了密文$ c1,c2$，计算$msg=c1\oplus c2=m1\oplus key\oplus m2\oplus key=m1\oplus m2$ 

2. 根据ASCii码表性质，**空格字符**与**小写字符**异或得到**大写字符**，**空格字符**与**大写字符**异或得到**小写字符**。

   | 字符 |    ascii码     |
   | :--: | :------------: |
   | 空格 | 20H: 00100000B |
   |  a   | 61H: 01100001B |
   |  A   | 41H: 01000001B |

   

​		由1，2知，如果获取的密文数量足够多，并把某一密文与其他密文异或，将结果格式化输出后得到：

> 字母多的列更有可能对应着明文的空格，'?'多的列更有可能对应着明文的字母，含有'?'列中优先选择大写字母，因为英文中小写字母出现的频率更高。



## 攻击案例实践

### 简介

​		本次实践主要使用python语言以及pycryptodome库实现，使用同一个key加密了11条明文语句。

​		攻击者期望通过这11条密文获取明文信息，并且还原出key，再用key解密其他明文。

### 实践过程

#### 准备过程

1. 人为创建11条明文，尽量选择了含义，单词长度各不相同的句子。

2. 使用pycryptodome库中Random模块获取一个随机的key,写入key.txt文件中。

3. 使用这个key加密11条明文，写入cipher.txt文件中。

   代码如下：

   ```python
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
   
   ```

   得到的密文及加密时间如下：

   ```
   0x9b40d24ea114785f149fe7e442b5a6146c007a2daf445b6f51c9c8d15668aaba465267ab4d6392253bef29399008bb08e870122ddc4a0fc43347a95c73948af4fcd730
   0xb8569b43a75a105810def6aa49acac0d6c49673aaf59402a1085c6dc4b6df8b6081731b95775893462ae683e9a18fa11e8345421d7066dc23540a65d66c0a8fef9dc
   0xac5ccd49a219011355d2f3e14eb0e30f6b496635fd494d3d108fc0cc1979f9ef5c5431a35a758f712db67b758b0ebb1fe5714037920323812a48b2417bda
   0xa05dde00b25d5d4f55cff3ee0baab0466f0c7c32ea4e5c2349c9dcdb5a79f8aa081731b75065db3223ad293b9a1dbf0ead764021d3016dc82e0da45d63da
   0x8c5fda55a251106f19c8fde54fe3900e7e07603be10d413c1082c1d14e62aaae5b1b70ee1d769a252aa67b75900dfa15e3725d36df0b39c83543e0467cd1a6eeec9b71
   0x885cd447aa511043069ffde44ee3ac003f1d6631af59473f10a8c2db4b65e9ae461b7cbb5364923f23b7603a910ab65cf971512cdc0521ce3d54e0517bd9b9fdfbd03410
   0x9b52c24ca946107902d6f4fe0baab04670076b74e04b083b588c8fdc5c7ffeef5b5e7da2567e9c712fb67a3c9c02bb12fe345d22920b21cd7a59a95f71
   0x8c5cd650b340555855ccf1e34eada0033f007d74fb454d6f439ddada402ce5a908587ea34f658f3036aa663bd34bbb09f97b5f25c60322cf760da15c7094a0f2f3d6230e53ad3142d9
   0xad5ad749a45d5c4355d6e1aa4ae3b50f7b0c6174fc45493d5987c89e4e69e8bc414f74ee5d71883426e3603bdf38b21de3735a25db4a61813359e04575c7e9f9e6cd30015eb02b4597d69832af157d07ace558
   0x9652d400b155430a06dafeef48b7a6023f0b7774fb454d6f6286ccd55c78f9ef494831ba5775db372bb17a21df04ac19ff755e28921a24c2310da95c34c0a1f9b58b615300
   0xb85bde4ee64143431bd8b2eb0bb0b7147a086374ec445827559b839e5769fcaa5a1b64bd5a308f3927e36230864bb713ff711230da0b23813543a357
   2022-11-17 22:46:06
   ```

#### 攻击过程

1. 选取1条最短密文，将其他10条密文与其进行异或。

2. 将10次异或结果格式化输出，分析其语言特性并尝试解密明文。

3. 使用解密的明文与密文异或，取得key。

4. 使用key将其他密文解密。

   代码如下：

   ```python
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
   
   ```

   得到的结果如下：

   ```
   #???GU;??GU?I??????YC??H?RKO??V??I???S????K??C???????A,E????
   ??E?A?S???DAB????A?NC???E?EB????R?U??E??EM???SM??EF???NC????
   ????DXBPN?A?E?T??A?A????E?CRN??E?OU??E?H?U?E?E????R?H???????
   ???NT???N?A????R???F?????R_E????R?U??UT??NK??V??R?R???NI?N??
   4???D?S,??O?DS'????O?I??E?BO??V????SGF???E?E?FM???O????I??C?
   0???L?S??GO?ES??E??EC???E3AE?????????T???T???A?O??C????O??C?
   #???O?S:??F????R??????P????B???E?E???N?H?U???I???EO?H??LO???
   4???U???N?C?E???E??????H??YD?E??RC???U???I??U?????M????NCN??
   ????B???N?SAAS????????????K??????T?S?A??????Ys????H??AB???C?
   .??NW??I??L?C???E??????H7?OK???E?SU??ET??R??YO????L?H??C?N??
   end
   ```


#### 人力破译过程

根据<u>攻击原理</u>中的规则，我们尝试进行破译，得到：

> ???n using a strea? cipher? never usg the key more ?han onc?

（?）表示字母未知

进一步还原和猜测知：

> ???n using a stream cipher, never use the key more than once 

根据语法分析，第一个单词应该为when

> when using a stream cipher, never use the key more than once 

至此，单一密文破解完毕。

#### 破解获得key和其他明文

将明文和密文相异或，得到key：

> 0xcf33bb20c634302a75bf928a2bc3c3661f690e548f2d284f30e9afbe390c8acf283b11ce3f10fb5142c30955ff6bda7c8d143244b26a4da15a2dc032

由于key的长度有限，获得的其他密文长度也有限。

解密得到的明文组如下：

​	'Tsing Hua university is a good university, located in Beijin'
​    'we can read books in the library , where makes me feel comfo'
​    'covid-19 makes it harder for us to meet our teachers in pers,
​    'one time pad is perfectly secure , you can never break it do,
​    'Claude Elwood Shannon is known as a "father of information t'
​    'Google is one of the top American multinational technology c'
​    'Taylor Swift is one of the best selling musicians of all tim'
​    'Computer science is the study of computation, automation, an,
​    'bilibili is a video sharing website based in Shanghai , it w'
​    'Yao was selected by the Rockets as the first overall pick in'

## 分析与总结	

​		通过以上的攻击过程，我们基本可以获得原文的主要信息，同时由于英文的冗余性，就算有几位key没有没破解，我们依旧可以通过语言学的方法来推测整个句子的语义。值得注意的是，我们获得的key是长度为166位的十六进制数，通过暴力枚举来破解的时间复杂度为 $2^{664}\approx 8\times 10^{199}$，基本接近于无穷。由此可见，多次使用同一个key会导致one time pad 失去安全性。

