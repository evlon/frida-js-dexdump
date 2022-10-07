# FRIDA-JS-DEXDump

`frida-js-dexdump` is a copy of frida-dexdump writed by ts.
It is a frida tool to find and dump dex in memory to support security engineers in analyzing malware.




## Features

1. Support fuzzy search broken header dex(deep search mode).
2. Compatible with all android version(frida supported).
3. One click installation, without modifying the system, easy to deploy and use.

## Installation

```
pip3 install frida frida-tools
npm install -g frida-fs-dexdump
```

## Usage

CLI arguments base on [frida-tools](https://github.com/frida/frida-tools), you can quickly dump the foreground application like this:

```
frida-js-dexdump -FU
```

Or use select to choice app like this:

```
frida-js-dexdump -U

? What app? (Use arrow keys)
❯ 2328:bin.mt.plus-MT管理器
  2492:com.android.flysilkworm-雷电游戏中心
  4171:com.xiaojianbang.app-HookTestDemo
  12477:com.android.settings-设置
  14633:com.android.documentsui-文件
```

Or specify and spawn app like this:

```
frida-js-dexdump -U -f com.app.pkgname
```

Or select install app and  spawn app like this:

```
frida-js-dexdump -U -f 


? What app? (Use arrow keys)
❯ bin.mt.plus(MT管理器)
  com.v2ray.ang(v2rayNG)
  com.xiaojianbang.app(HookTestDemo)
  com.yssenlin.app(影视森林)
  lnes.ef(一起设置)
  magisk.term(Magisk Terminal Emulator)
  player.normal.np(NP管理器)
```

 
Additionally, you can see in `-h` that the new options provided by frida-dexdump are: 

```
-o OUTPUT, --output OUTPUT  Output folder path, default is './<appname>/'.
-d, --deep-search           Enable deep search mode.
--sleep SLEEP               Waiting times for start, spawn mode default is 5s.
```

When using, I suggest using the `-d, --deep-search` option, which may take more time, but the results will be more complete.

## Build and develop

```
yarn install
yarn run watch-agent
yarn run watch
```

### 参考和致谢

See [hluwa](https://github.com/hluwa/FRIDA-DEXDump/)
[《深入 FRIDA-DEXDump 中的矛与盾》](https://mp.weixin.qq.com/s/n2XHGhshTmvt2FhxyFfoMA)


