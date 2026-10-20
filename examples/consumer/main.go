// consumer 是消费者代码的演示：只用 Evaluate 和 Judge 两步，换来源不改一行。
// 在仓库根目录运行：go run ./examples/consumer -src=tdx -case=bad
package main

import (
	"flag"
	"fmt"

	"github.com/buska88/trustlib"
	"github.com/buska88/trustlib/examples/samples"
)

func main() {
	src, kase := flag.String("src", "tdx", "ear | tdx | tpm"), flag.String("case", "good", "good | bad")
	flag.Parse()
	ev, req := samples.Must(*src, *kase)
	res, err := ev.Evaluate(req)
	v := trustlib.Judge(res, err, trustlib.DefaultMask)
	fmt.Printf("%s/%-4s tier=%-15s decisive=%v err=%v\n", *src, *kase, v.Tier, v.Decisive, v.Err)
}
