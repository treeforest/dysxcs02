package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/treeforest/dysxcs02/sdf"
)

func main() {
	if _, err := os.Stat("cacipher.ini"); err != nil {
		fmt.Fprintln(os.Stderr, "请将 testdata/cacipher.ini 复制到当前工作目录")
		os.Exit(1)
	}

	dev, err := sdf.OpenDeviceWithConfig("cacipher.ini", nil)
	if err != nil {
		log.Fatalf("打开设备失败: %v", err)
	}
	defer dev.Close()

	sess, err := dev.OpenSession()
	if err != nil {
		log.Fatalf("打开会话失败: %v", err)
	}
	defer sess.Close()

	info, err := sess.GetDeviceInfo()
	if err != nil {
		log.Fatalf("获取设备信息失败: %v", err)
	}
	fmt.Printf("设备名称: %s\n", strings.TrimRight(string(info.DeviceName[:]), "\x00"))
	fmt.Printf("设备版本: %d\n", info.DeviceVersion)

	rand, err := sess.GenerateRandom(16)
	if err != nil {
		log.Fatalf("生成随机数失败: %v", err)
	}
	fmt.Printf("随机数 (16B): %x\n", rand)
}
