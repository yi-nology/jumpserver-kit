// jumpserver-kit —— JumpServer MCP 的共用底座。
//
// 这是**库**，不是可执行程序：协议层（pkg/jmsapi）、工具注册与门禁
// （pkg/reg）、结果整形与输出契约（pkg/render）、工具调用留痕（pkg/audit）、
// 凭据脱敏（pkg/redact）、命令风险分类（pkg/risk）、失败分类（pkg/errs）、
// 契约守卫的机械（pkg/contractscan），以及两个服务共用的词汇（model/jms）。
//
// 它**不认识任何一个服务**：底座一旦伸手进某个服务，就不再是共用的，
// 而是那个服务披着共用名字的私有代码（另一个服务迟早也会伸手进去，
// 两个服务就这么耦上了，而没有人决定过）。
//
// 发版节奏：**只在底座的公开 API 变了才发版**。两个服务仓各自 require 一个
// 版本；改动底座 ⇒ 先发 kit 的 tag ⇒ 再更新两个服务的 require ⇒ 再发服务。
// 底座的版本是**承诺**：语义化版本，破坏性改动走 major。
//
// ⚠️ 不写 replace（依赖按普通方式解析，go.sum 钉住内容）：
// 指向本机路径的 replace 会让 go.mod 与机器绑定，go list -m 报的是路径
// 而不是版本，require 里的版本号变成一句空话。

module github.com/yi-nology/jumpserver-kit

go 1.26.0

require (
	github.com/cloudwego/gopkg v0.2.1
	github.com/cloudwego/kitex v0.16.4
	github.com/google/jsonschema-go v0.4.3
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/oagentkit/guardx v0.19.0
	github.com/oagentkit/tools v0.12.0
	github.com/oekit/bootstrap v0.6.8
	github.com/oekit/concurrency v0.25.1
	github.com/oekit/core v0.12.2
	github.com/oekit/kitex v0.7.6
	github.com/oekit/logx v0.8.3
	github.com/oekit/pkg v0.34.1
	github.com/pquerna/otp v1.5.0
	golang.org/x/time v0.16.0
	gopkg.in/yaml.v3 v3.0.1
	mvdan.cc/sh/v3 v3.14.1
)

require (
	github.com/alibabacloud-go/alibabacloud-gateway-pop v0.0.6 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-spi v0.0.5 // indirect
	github.com/alibabacloud-go/darabonba-array v0.1.0 // indirect
	github.com/alibabacloud-go/darabonba-encode-util v0.0.2 // indirect
	github.com/alibabacloud-go/darabonba-map v0.0.2 // indirect
	github.com/alibabacloud-go/darabonba-openapi/v2 v2.0.10 // indirect
	github.com/alibabacloud-go/darabonba-signature-util v0.0.7 // indirect
	github.com/alibabacloud-go/darabonba-string v1.0.2 // indirect
	github.com/alibabacloud-go/debug v1.0.1 // indirect
	github.com/alibabacloud-go/endpoint-util v1.1.0 // indirect
	github.com/alibabacloud-go/kms-20160120/v3 v3.2.3 // indirect
	github.com/alibabacloud-go/openapi-util v0.1.0 // indirect
	github.com/alibabacloud-go/tea v1.2.2 // indirect
	github.com/alibabacloud-go/tea-utils v1.4.4 // indirect
	github.com/alibabacloud-go/tea-utils/v2 v2.0.7 // indirect
	github.com/alibabacloud-go/tea-xml v1.1.3 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1800 // indirect
	github.com/aliyun/alibabacloud-dkms-gcs-go-sdk v0.5.1 // indirect
	github.com/aliyun/alibabacloud-dkms-transfer-go-sdk v0.1.8 // indirect
	github.com/aliyun/aliyun-secretsmanager-client-go v1.1.5 // indirect
	github.com/aliyun/credentials-go v1.4.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/bytedance/gopkg v0.1.4 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clbanning/mxj/v2 v2.5.5 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/cloudwego/configmanager v0.2.3 // indirect
	github.com/cloudwego/dynamicgo v0.9.2 // indirect
	github.com/cloudwego/fastpb v0.0.6 // indirect
	github.com/cloudwego/frugal v0.3.1 // indirect
	github.com/cloudwego/localsession v0.2.2 // indirect
	github.com/cloudwego/netpoll v0.7.5 // indirect
	github.com/cloudwego/runtimex v0.1.2 // indirect
	github.com/cloudwego/thriftgo v0.4.5 // indirect
	github.com/deckarep/golang-set v1.7.1 // indirect
	github.com/fatih/structtag v1.2.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/jhump/protoreflect v1.8.2 // indirect
	github.com/jmespath/go-jmespath v0.0.0-20180206201540-c2b33e8439af // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kitex-contrib/resolver-dns v0.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nacos-group/nacos-sdk-go/v2 v2.3.6-0.20260601044846-0e3d1d099507 // indirect
	github.com/oekit/logx/kitexlog v0.1.8 // indirect
	github.com/oekit/metrics v0.1.11 // indirect
	github.com/orcaman/concurrent-map v0.0.0-20210501183033-44dafcb38ecc // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.25.0 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/arch v0.14.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)
