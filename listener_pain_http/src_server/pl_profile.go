package main

import (
    "encoding/json"
    "fmt"
    "strings"
)

func isValidHex(s string) bool {
    if len(s) != 2 {
        return false
    }
    for _, c := range s {
        if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            return false
        }
    }
    return true
}

func convertHexEscapes(input string) string {
    var result []byte
    i := 0
    for i < len(input) {
        if i < len(input)-3 && input[i] == '\\' && input[i+1] == 'x' {
            hexStr := input[i+2 : i+4]
            if isValidHex(hexStr) {
                var b byte
                fmt.Sscanf(hexStr, "%02x", &b)
                result = append(result, b)
                i += 4
                continue
            }
        }
        result = append(result, input[i])
        i++
    }
    return string(result)
}

func parseOutputConfig(raw interface{}) *OutputConfig {
    if raw == nil {
        return nil
    }
    m, ok := raw.(map[string]interface{})
    if !ok {
        return nil
    }
    out := &OutputConfig{}
    if v, ok := m["mask"].(bool); ok {
        out.Mask = v
    }
    if v, ok := m["format"].(string); ok {
        out.Format = v
    }
    if v, ok := m["header"].(string); ok {
        out.Header = convertHexEscapes(v)
    }
    if v, ok := m["parameter"].(string); ok {
        out.Parameter = convertHexEscapes(v)
    }
    if v, ok := m["cookie"].(string); ok {
        out.Cookie = convertHexEscapes(v)
    }
    if v, ok := m["body"].(string); ok {
        out.Body = convertHexEscapes(v)
    }
    if v, ok := m["prepend"].(string); ok {
        out.Prepend = convertHexEscapes(v)
    }
    if v, ok := m["append"].(string); ok {
        out.Append = convertHexEscapes(v)
    }
    return out
}

func parseHTTPMethod(raw map[string]interface{}) *HTTPMethod {
    method := &HTTPMethod{
        ServerHeaders: make(map[string]string),
        ClientHeaders: make(map[string]string),
        URI:           make(map[string]URIConfig),
    }

    if sh, ok := raw["server_headers"].(map[string]interface{}); ok {
        for k, v := range sh {
            method.ServerHeaders[k] = v.(string)
        }
    }
    if ch, ok := raw["client_headers"].(map[string]interface{}); ok {
        for k, v := range ch {
            method.ClientHeaders[k] = v.(string)
        }
    }
    if er, ok := raw["empty_response"].(string); ok {
        method.EmptyResponse = []byte(convertHexEscapes(er))
    }

    if uriRaw, ok := raw["uri"].(map[string]interface{}); ok {
        for uriKey, uriData := range uriRaw {
            uriMap, ok := uriData.(map[string]interface{})
            if !ok {
                continue
            }
            // A single key can have space-separated paths: "/search /query"
            for _, path := range strings.Fields(uriKey) {
                cfg := URIConfig{
                    ServerOutput: parseOutputConfig(uriMap["server_output"]),
                    ClientOutput: parseOutputConfig(uriMap["client_output"]),
                }
                if cpRaw, ok := uriMap["client_parameters"].([]interface{}); ok {
                    for _, cp := range cpRaw {
                        if pm, ok := cp.(map[string]interface{}); ok {
                            copy := make(map[string]interface{})
                            for k, v := range pm {
                                copy[k] = v
                            }
                            cfg.ClientParams = append(cfg.ClientParams, copy)
                        }
                    }
                }
                method.URI[path] = cfg
            }
        }
    }
    return method
}

func parseProfile(listener *HTTPListener, profileJSON string) ([]Callback, error) {
    var root map[string]interface{}
    if err := json.Unmarshal([]byte(profileJSON), &root); err != nil {
        return nil, fmt.Errorf("profile JSON parse error: %w", err)
    }

    rawCallbacks, ok := root["callbacks"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("profile missing 'callbacks' array")
    }

    var callbacks []Callback
    var addresses []string

    for _, item := range rawCallbacks {
        cbMap, ok := item.(map[string]interface{})
        if !ok {
            continue
        }

        cb := Callback{
            UserAgent: cbMap["user_agent"].(string),
        }

        // server_error
        if seRaw, ok := cbMap["server_error"].(map[string]interface{}); ok {
            se := &ServerError{}
            if v, ok := seRaw["http_status"].(float64); ok {
                se.Status = int(v)
            }
            if v, ok := seRaw["response"].(string); ok {
                se.Response = v
            }
            se.Headers = make(map[string]string)
            if hRaw, ok := seRaw["headers"].(map[string]interface{}); ok {
                for k, v := range hRaw {
                    se.Headers[k] = v.(string)
                }
            }
            cb.SrvError = se
        }

        // get / post
        if getRaw, ok := cbMap["get"].(map[string]interface{}); ok {
            cb.Get = parseHTTPMethod(getRaw)
        }
        if postRaw, ok := cbMap["post"].(map[string]interface{}); ok {
            cb.Post = parseHTTPMethod(postRaw)
        }

        // hosts - one Callback entry per host
        if hostsRaw, ok := cbMap["hosts"].([]interface{}); ok {
            for _, h := range hostsRaw {
                host := h.(string)
                cb.Hosts = append(cb.Hosts, host)
                addresses = append(addresses, host)
            }
        }

        callbacks = append(callbacks, cb)
    }

    listener.Config.Addresses = strings.Join(addresses, ",")
    return callbacks, nil
}
