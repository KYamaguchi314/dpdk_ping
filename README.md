# dpdk-ping

DPDKでpingをするプログラム

機能

- NICになるべく近い部分で送受信時のタイムスタンプ取得
- 簡易プロトコルスタック（ARP, ICMP）

## 準備

### IPアドレスの設定

`protocol.h`の下記の部分を書き換える

```cpp
uint32_t my_ipaddr = RTE_IPV4(10, 255, 0, 2);
uint32_t target_ipaddr = RTE_IPV4(10, 255, 0, 1);
```

もしくは、対向ポートにIPアドレスを振る

```sh
sudo ip addr add 10.255.0.1/24 dev eth1
sudo ip link set eth1 up
```

### CPU周波数の固定

正確にRTTを求めるため、CPU周波数を固定する

```sh
# ハードウェア的な周波数の上限・下限を確認
sudo cpupower frequency-info

# CPUの動作周波数を固定する
# ハードウェア制限に対して少し余裕を持たせる
sudo cpupower frequency-set -f 2.80GHz
```

## 実行方法

### pingに対応したホストに送信する場合

```sh
make

./build/dpdk-ping -a 0000:01:00.0
```

### DPDKどうしで送受信する場合

```sh
# Makefileの下記の行を有効化
CFLAGS += -DDPDK_BOUNCE

make

./build/dpdk-ping -a 0000:01:00.0 -a 0000:01:00.1
```

- 注意: 対向ポートではICMP Requestを送り返しているだけである。ICMP Replyは行われない。
