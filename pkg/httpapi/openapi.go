package httpapi

import (
	"encoding/json"
	"fmt"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// OpenAPI renders this HTTP surface as an OpenAPI 3.1 document.
//
// ⚠️ 同源是这里的**机制**，不是口号：文档里的每个工具形状都取自注册表
// 在装配时捕获的 schema，而那正是 MCP 工具列表给模型看的同一份 ——
// Go 类型派生的入参形状、idl/ 契约（thrift 生成物）派生的出参形状。
// 手写一份 OpenAPI 必然与它服务的工具漂移；生成的一份不会。
//
// The document is generated, byte-stable (the same catalogue renders the
// same bytes), and checked in under swagger/ — a stale copy is caught by
// the service's own guard.
func OpenAPI(r *reg.Registry, opts Options) ([]byte, error) {
	schemas := map[string]any{
		"InvokeResult": invokeResultSchema(),
		"Error":        errorSchema(),
	}
	paths := map[string]any{
		"/api/v1/health": map[string]any{
			"get": map[string]any{
				"summary":     "存活探针（唯一不需要令牌的路由）",
				"security":    []any{},
				"operationId": "health",
				"responses": map[string]any{
					"200": jsonResponse("服务在跑", map[string]any{
						"type": "object",
						"properties": map[string]any{
							"status":    map[string]any{"type": "string"},
							"server":    map[string]any{"type": "string"},
							"version":   map[string]any{"type": "string"},
							"read_only": map[string]any{"type": "boolean"},
							"tools":     map[string]any{"type": "integer"},
						},
					}),
				},
			},
		},
		"/api/v1/tools": map[string]any{
			"get": map[string]any{
				"summary":     "工具目录：名字、风险、确认要求、入参/出参形状",
				"operationId": "listTools",
				"responses": map[string]any{
					"200": jsonResponse("目录", map[string]any{
						"type": "object",
						"properties": map[string]any{
							"tools": map[string]any{
								"type": "array",
								"items": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"name":          map[string]any{"type": "string"},
										"description":   map[string]any{"type": "string"},
										"risk":          map[string]any{"type": "string"},
										"confirm":       map[string]any{"type": "string"},
										"input_schema":  map[string]any{},
										"output_schema": map[string]any{},
									},
								},
							},
						},
					}),
				},
			},
		},
		"/mcp": map[string]any{
			"post": map[string]any{
				"summary":     "MCP over streamable HTTP（JSON-RPC；GET 是事件流，DELETE 结束会话）",
				"operationId": "mcpStream",
				"requestBody": map[string]any{
					"required": true,
					"content":  map[string]any{"application/json": map[string]any{"schema": map[string]any{}}},
				},
				"responses": map[string]any{
					"200": jsonResponse("JSON-RPC 应答（或 SSE 流）", map[string]any{}),
				},
			},
		},
	}

	for _, spec := range r.Specs() {
		in, out, _ := r.Schema(spec.Name)
		inputName := "ToolInput_" + spec.Name
		schemas[inputName] = schemaOrObject(in)

		resultRef := map[string]any{"$ref": "#/components/schemas/InvokeResult"}
		if len(out) > 0 {
			outputName := "ToolOutput_" + spec.Name
			schemas[outputName] = json.RawMessage(out)
			resultName := "ToolResult_" + spec.Name
			schemas[resultName] = map[string]any{
				"allOf": []any{
					map[string]any{"$ref": "#/components/schemas/InvokeResult"},
					map[string]any{
						"type":       "object",
						"properties": map[string]any{"structured": map[string]any{"$ref": "#/components/schemas/" + outputName}},
					},
				},
			}
			resultRef = map[string]any{"$ref": "#/components/schemas/" + resultName}
		}

		desc := spec.Description
		if spec.Risk.String() != "" {
			desc = fmt.Sprintf("[risk: %s] %s", spec.Risk.String(), desc)
		}
		if spec.Confirm != nil && *spec.Confirm != "" {
			desc += fmt.Sprintf("（需确认：%s）", *spec.Confirm)
		}
		paths["/api/v1/tools/"+spec.Name+"/invoke"] = map[string]any{
			"post": map[string]any{
				"summary":     "调用工具 " + spec.Name,
				"description": desc,
				"operationId": "invoke_" + spec.Name,
				"requestBody": map[string]any{
					"required": true,
					"content": map[string]any{
						"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/" + inputName}},
					},
				},
				"responses": map[string]any{
					"200": jsonResponse("调用完成（is_error 说明结果；拒绝、失败与入参不合形状也是 200，与 stdio 应答逐字相同）", resultRef),
					"400": jsonResponse("请求本身坏了（body 不是 JSON 对象 / 读不出 / 太大）", map[string]any{"$ref": "#/components/schemas/Error"}),
					"404": jsonResponse("没有这个工具", map[string]any{"$ref": "#/components/schemas/Error"}),
					"500": jsonResponse("服务端没能把调用送到工具（会话/传输层故障）", map[string]any{"$ref": "#/components/schemas/Error"}),
				},
			},
		}
	}

	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   opts.Name + " HTTP API",
			"version": opts.Version,
			"description": "自动生成（`tools openapi`），与 MCP 工具目录同源：" +
				"入参/出参形状取自注册表装配时捕获的 schema（出参来自 idl/ 契约的生成物）。" +
				"所有工具调用与 stdio 共用同一道风险门禁、确认语义与留痕。" +
				"拒绝与失败的调用返回 HTTP 200 + is_error=true（请求没错，结果是拒绝）。",
		},
		"security": []any{map[string]any{"bearerAuth": []any{}}},
		"paths":    paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer"},
			},
			"schemas": schemas,
		},
	}
	// Go marshals map keys sorted, so the same catalogue renders the same
	// bytes — the checked-in copy can be diffed against a regeneration.
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// invokeResultSchema is the REST envelope every invoke answers in.
func invokeResultSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"tool", "is_error", "text"},
		"properties": map[string]any{
			"tool":       map[string]any{"type": "string"},
			"is_error":   map[string]any{"type": "boolean"},
			"text":       map[string]any{"type": "string"},
			"structured": map[string]any{},
		},
	}
}

// errorSchema is the shape of a request-level error answer.
func errorSchema() map[string]any {
	return map[string]any{
		"type":       "object",
		"required":   []string{"error"},
		"properties": map[string]any{"error": map[string]any{"type": "string"}},
	}
}

// schemaOrObject renders a captured schema, or the open object when the
// tool captured none.
func schemaOrObject(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{"type": "object", "additionalProperties": true}
	}
	return json.RawMessage(raw)
}

// jsonResponse wraps a schema in a 200 JSON response.
func jsonResponse(desc string, schema any) map[string]any {
	return map[string]any{
		"description": desc,
		"content": map[string]any{
			"application/json": map[string]any{"schema": schema},
		},
	}
}
