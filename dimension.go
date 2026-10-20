package trustlib

import (
	"fmt"
	"strings"
)

// Dimension 是 AR4SI 定义的八个可信度维度（draft-ietf-rats-ar4si-10 §2.3.4）。
// 顺序与 veraison/ear 的 TrustVector 字段顺序一致。
type Dimension uint8

const (
	InstanceIdentity Dimension = iota // instance-identity：是不是预期的那个实例
	Configuration                     // configuration：配置
	Executables                       // executables：加载运行的程序
	FileSystem                        // file-system：一组特定目录
	Hardware                          // hardware：硬件与固件
	RuntimeOpaque                     // runtime-opaque：运行时内存对外是否不可见
	StorageOpaque                     // storage-opaque：能否加密持久存储
	SourcedData                       // sourced-data：外部数据是否可信
)

// NumDimensions 是维度的个数。
const NumDimensions = 8

var dimensionNames = [NumDimensions]string{
	"instance-identity",
	"configuration",
	"executables",
	"file-system",
	"hardware",
	"runtime-opaque",
	"storage-opaque",
	"sourced-data",
}

// String 返回 AR4SI 里的维度名，例如 "hardware"。
func (d Dimension) String() string {
	if int(d) < NumDimensions {
		return dimensionNames[d]
	}
	return fmt.Sprintf("dimension(%d)", uint8(d))
}

// AllDimensions 按固定顺序返回全部八维。
func AllDimensions() []Dimension {
	ds := make([]Dimension, NumDimensions)
	for i := range ds {
		ds[i] = Dimension(i)
	}
	return ds
}

// Mask 用比特位表示调用方关注哪些维度：第 d 位为 1，表示关注 Dimension d。
type Mask uint8

// DefaultMask 是默认的关键维：hardware、configuration、executables。
// 这是三种来源都判得了的维。把来源判断不了的维（比如 file-system）放进来，
// 塌缩结果会永远是无结论（docs/design.md D3）。
const DefaultMask = Mask(1<<Hardware | 1<<Configuration | 1<<Executables)

// MaskOf 由若干维度组成掩码。
func MaskOf(dims ...Dimension) Mask {
	var m Mask
	for _, d := range dims {
		m |= 1 << d
	}
	return m
}

// Has 报告掩码里是否有维度 d。
func (m Mask) Has(d Dimension) bool { return m&(1<<d) != 0 }

// Dimensions 按固定顺序返回掩码里的维度。
func (m Mask) Dimensions() []Dimension {
	var ds []Dimension
	for _, d := range AllDimensions() {
		if m.Has(d) {
			ds = append(ds, d)
		}
	}
	return ds
}

// String 以 "configuration|executables|hardware" 的形式打印掩码。
func (m Mask) String() string {
	names := make([]string, 0, NumDimensions)
	for _, d := range m.Dimensions() {
		names = append(names, d.String())
	}
	return strings.Join(names, "|")
}

// Vector 是八维的原始取值（AR4SI §2.3.2 的有符号 8 位整数），下标是 Dimension。
// 0 表示这一维没有声明：AR4SI §2.3.2 要求依赖方把 0 和“没给出”同等对待。
type Vector [NumDimensions]int8

// String 以 "instance-identity=0 configuration=2 ..." 的形式打印全部八维。
func (v Vector) String() string {
	parts := make([]string, 0, NumDimensions)
	for _, d := range AllDimensions() {
		parts = append(parts, fmt.Sprintf("%s=%d", d, v[d]))
	}
	return strings.Join(parts, " ")
}
