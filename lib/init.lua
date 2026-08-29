local ffi = require 'ffi'
local bit = require 'bit'

local M = {
    _VERSION = '1.0.0',
    backend = 'WinHTTP/Schannel'
}

ffi.cdef[[
    typedef unsigned long PM_DWORD_PTR;
    void* __stdcall WinHttpOpen(
        const wchar_t* pwszUserAgent,
        unsigned long dwAccessType,
        const wchar_t* pwszProxyName,
        const wchar_t* pwszProxyBypass,
        unsigned long dwFlags
    );

    void* __stdcall WinHttpConnect(
        void* hSession,
        const wchar_t* pswzServerName,
        unsigned short nServerPort,
        unsigned long dwReserved
    );

    void* __stdcall WinHttpOpenRequest(
        void* hConnect,
        const wchar_t* pwszVerb,
        const wchar_t* pwszObjectName,
        const wchar_t* pwszVersion,
        const wchar_t* pwszReferrer,
        const wchar_t** ppwszAcceptTypes,
        unsigned long dwFlags
    );

    int __stdcall WinHttpSetTimeouts(
        void* hInternet,
        int nResolveTimeout,
        int nConnectTimeout,
        int nSendTimeout,
        int nReceiveTimeout
    );

    int __stdcall WinHttpSetOption(
        void* hInternet,
        unsigned long dwOption,
        void* lpBuffer,
        unsigned long dwBufferLength
    );

    int __stdcall WinHttpSendRequest(
        void* hRequest,
        const wchar_t* lpszHeaders,
        unsigned long dwHeadersLength,
        const void* lpOptional,
        unsigned long dwOptionalLength,
        unsigned long dwTotalLength,
        PM_DWORD_PTR dwContext
    );

    int __stdcall WinHttpReceiveResponse(
        void* hRequest,
        void* lpReserved
    );

    int __stdcall WinHttpReadData(
        void* hRequest,
        void* lpBuffer,
        unsigned long dwNumberOfBytesToRead,
        unsigned long* lpdwNumberOfBytesRead
    );

    int __stdcall WinHttpQueryHeaders(
        void* hRequest,
        unsigned long dwInfoLevel,
        const wchar_t* pwszName,
        void* lpBuffer,
        unsigned long* lpdwBufferLength,
        unsigned long* lpdwIndex
    );

    int __stdcall WinHttpCloseHandle(void* hInternet);

    int __stdcall MultiByteToWideChar(
        unsigned int CodePage,
        unsigned long dwFlags,
        const char* lpMultiByteStr,
        int cbMultiByte,
        wchar_t* lpWideCharStr,
        int cchWideChar
    );

    int __stdcall WideCharToMultiByte(
        unsigned int CodePage,
        unsigned long dwFlags,
        const wchar_t* lpWideCharStr,
        int cchWideChar,
        char* lpMultiByteStr,
        int cbMultiByte,
        const char* lpDefaultChar,
        int* lpUsedDefaultChar
    );

    unsigned long __stdcall GetLastError(void);
    unsigned long __stdcall FormatMessageA(
        unsigned long dwFlags,
        const void* lpSource,
        unsigned long dwMessageId,
        unsigned long dwLanguageId,
        char* lpBuffer,
        unsigned long nSize,
        void* Arguments
    );

    int __stdcall MoveFileExW(
        const wchar_t* lpExistingFileName,
        const wchar_t* lpNewFileName,
        unsigned long dwFlags
    );
    int __stdcall DeleteFileW(const wchar_t* lpFileName);
]]

local winhttp = ffi.load('winhttp')
local kernel32 = ffi.load('kernel32')

local CP_ACP = 0
local CP_UTF8 = 65001
local WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
local WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
local WINHTTP_FLAG_SECURE = 0x00800000
local WINHTTP_OPTION_DECOMPRESSION = 118
local WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL = 133
local WINHTTP_OPTION_IPV6_FAST_FALLBACK = 140
local WINHTTP_PROTOCOL_FLAG_HTTP2 = 0x00000001
local WINHTTP_DECOMPRESSION_FLAG_GZIP = 0x00000001
local WINHTTP_DECOMPRESSION_FLAG_DEFLATE = 0x00000002
local WINHTTP_QUERY_STATUS_CODE = 19
local WINHTTP_QUERY_RAW_HEADERS_CRLF = 22
local WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
local ERROR_INSUFFICIENT_BUFFER = 122
local MOVEFILE_REPLACE_EXISTING = 0x00000001
local MOVEFILE_WRITE_THROUGH = 0x00000008

local DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36'
local DEFAULT_TIMEOUT_SECONDS = 15
local DEFAULT_MAX_BODY_SIZE = 64 * 1024 * 1024

local ERROR_CODES = {
    [12002] = 'HTTP_TIMEOUT',
    [12007] = 'HTTP_DNS',
    [12017] = 'HTTP_CANCELLED',
    [12029] = 'HTTP_CONNECT',
    [12030] = 'HTTP_CLOSED',
    [12032] = 'HTTP_NETWORK',
    [12037] = 'HTTP_TLS',
    [12038] = 'HTTP_TLS',
    [12044] = 'HTTP_TLS',
    [12045] = 'HTTP_TLS',
    [12150] = 'HTTP_HEADERS',
    [12152] = 'HTTP_PROTOCOL',
    [12157] = 'HTTP_TLS',
    [12175] = 'HTTP_TLS'
}

local function is_null(value)
    return value == nil or value == ffi.NULL
end

local function to_wide_cp(value, code_page)
    value = tostring(value or '')
    if value == '' then
        return ffi.new('wchar_t[1]', 0), 0
    end
    local required = kernel32.MultiByteToWideChar(code_page, 0, value, #value, nil, 0)
    if required <= 0 then
        return nil
    end
    local buffer = ffi.new('wchar_t[?]', required + 1)
    local written = kernel32.MultiByteToWideChar(code_page, 0, value, #value, buffer, required)
    if written <= 0 then
        return nil
    end
    buffer[written] = 0
    return buffer, written
end

local function to_wide(value)
    return to_wide_cp(value, CP_UTF8)
end

local function to_wide_path(value)
    return to_wide_cp(value, CP_ACP)
end

local function from_wide(buffer, char_count)
    if is_null(buffer) then return '' end
    char_count = tonumber(char_count) or -1
    local required = kernel32.WideCharToMultiByte(CP_UTF8, 0, buffer, char_count, nil, 0, nil, nil)
    if required <= 0 then return '' end
    local out = ffi.new('char[?]', required + 1)
    local written = kernel32.WideCharToMultiByte(CP_UTF8, 0, buffer, char_count, out, required, nil, nil)
    if written <= 0 then return '' end
    local result = ffi.string(out, written)
    if char_count == -1 and #result > 0 and result:byte(-1) == 0 then
        result = result:sub(1, -2)
    end
    return result
end

local function system_error_message(code)
    code = tonumber(code) or 0
    local buffer = ffi.new('char[1024]')
    local length = kernel32.FormatMessageA(0x00001200, nil, code, 0, buffer, 1024, nil)
    local message
    if length > 0 then
        message = ffi.string(buffer, length):gsub('[\r\n]+$', '')
    else
        message = 'Windows error ' .. tostring(code)
    end
    return message
end

local function make_error(stage, native_code, override_code, message, extra)
    native_code = tonumber(native_code) or 0
    local err = {
        code = override_code or ERROR_CODES[native_code] or 'HTTP_NETWORK',
        stage = tostring(stage or 'network'),
        native_code = native_code,
        message = tostring(message or system_error_message(native_code))
    }
    if type(extra) == 'table' then
        for key, value in pairs(extra) do err[key] = value end
    end
    return err
end

local function last_error(stage, override_code, extra)
    local code = tonumber(kernel32.GetLastError()) or 0
    return make_error(stage, code, override_code, nil, extra)
end

local function parse_url(url)
    url = tostring(url or '')
    local scheme, rest = url:match('^([Hh][Tt][Tt][Pp][Ss]?)://(.+)$')
    if not scheme then
        return nil, make_error('url', 0, 'HTTP_URL', 'Only http:// and https:// URLs are supported')
    end
    scheme = scheme:lower()

    local split_pos = rest:find('[/%?#]')
    local authority
    local target
    if split_pos then
        authority = rest:sub(1, split_pos - 1)
        target = rest:sub(split_pos)
    else
        authority = rest
        target = '/'
    end

    if authority == '' or authority:find('@', 1, true) then
        return nil, make_error('url', 0, 'HTTP_URL', 'Invalid URL authority')
    end

    local host, port
    if authority:sub(1, 1) == '[' then
        host, port = authority:match('^%[([^%]]+)%]:(%d+)$')
        if not host then host = authority:match('^%[([^%]]+)%]$') end
    else
        host, port = authority:match('^(.+):(%d+)$')
        if not host then host = authority end
    end

    if not host or host == '' then
        return nil, make_error('url', 0, 'HTTP_URL', 'URL host is empty')
    end

    local fragment_pos = target:find('#', 1, true)
    if fragment_pos then target = target:sub(1, fragment_pos - 1) end
    if target == '' then target = '/' end
    if target:sub(1, 1) == '?' then target = '/' .. target end

    port = tonumber(port) or (scheme == 'https' and 443 or 80)
    if port < 1 or port > 65535 then
        return nil, make_error('url', 0, 'HTTP_URL', 'Invalid URL port')
    end

    return {
        scheme = scheme,
        secure = scheme == 'https',
        host = host,
        port = port,
        target = target,
        original = url
    }
end

local function has_header(headers, wanted)
    wanted = wanted:lower()
    for key in pairs(headers or {}) do
        if tostring(key):lower() == wanted then return true end
    end
    return false
end

local function build_headers(headers, user_agent)
    local result = {}
    headers = headers or {}
    for key, value in pairs(headers) do
        if value ~= nil then
            result[#result + 1] = tostring(key) .. ': ' .. tostring(value)
        end
    end
    if not has_header(headers, 'accept') then
        result[#result + 1] = 'Accept: */*'
    end
    if #result == 0 then return nil end
    return table.concat(result, '\r\n') .. '\r\n'
end

local function parse_raw_headers(raw)
    local headers = {}
    local first = true
    for line in tostring(raw or ''):gmatch('([^\r\n]+)') do
        if first then
            first = false
        else
            local key, value = line:match('^([^:]+):%s*(.*)$')
            if key then
                local normalized = key:lower()
                if headers[normalized] == nil then
                    headers[normalized] = value
                else
                    headers[normalized] = tostring(headers[normalized]) .. ', ' .. value
                end
            end
        end
    end
    return headers
end

local function query_status_code(request)
    local status = ffi.new('unsigned long[1]', 0)
    local size = ffi.new('unsigned long[1]', ffi.sizeof(status))
    local ok = winhttp.WinHttpQueryHeaders(
        request,
        bit.bor(WINHTTP_QUERY_STATUS_CODE, WINHTTP_QUERY_FLAG_NUMBER),
        nil,
        status,
        size,
        nil
    )
    if ok == 0 then
        return nil, last_error('query_status', 'HTTP_PROTOCOL')
    end
    return tonumber(status[0]) or 0
end

local function query_raw_headers(request)
    local size = ffi.new('unsigned long[1]', 0)
    winhttp.WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, nil, nil, size, nil)
    local needed = tonumber(size[0]) or 0
    if needed <= 0 then return '' end
    local last = tonumber(kernel32.GetLastError()) or 0
    if last ~= ERROR_INSUFFICIENT_BUFFER then return '' end
    local buffer = ffi.new('unsigned char[?]', needed + 2)
    local ok = winhttp.WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, nil, buffer, size, nil)
    if ok == 0 then return '' end
    return from_wide(ffi.cast('wchar_t*', buffer), math.floor((tonumber(size[0]) or 0) / 2)):gsub('%z+$', '')
end

local function read_body(request, max_body_size)
    max_body_size = tonumber(max_body_size) or DEFAULT_MAX_BODY_SIZE
    if max_body_size <= 0 then max_body_size = DEFAULT_MAX_BODY_SIZE end

    local chunks = {}
    local total = 0
    local buffer_size = 64 * 1024
    local buffer = ffi.new('unsigned char[?]', buffer_size)
    local read = ffi.new('unsigned long[1]', 0)

    while true do
        read[0] = 0
        local ok = winhttp.WinHttpReadData(request, buffer, buffer_size, read)
        if ok == 0 then
            return nil, last_error('read')
        end
        local count = tonumber(read[0]) or 0
        if count == 0 then break end
        total = total + count
        if total > max_body_size then
            return nil, make_error('read', 0, 'HTTP_BODY_TOO_LARGE', 'Response body exceeded the configured limit', {
                max_body_size = max_body_size,
                received = total
            })
        end
        chunks[#chunks + 1] = ffi.string(buffer, count)
    end

    return table.concat(chunks)
end

local function close_handle(handle)
    if not is_null(handle) then pcall(winhttp.WinHttpCloseHandle, handle) end
end

function M.request(method, url, args)
    args = args or {}
    method = tostring(method or 'GET'):upper()

    local parsed, parse_err = parse_url(url)
    if not parsed then return nil, parse_err end

    local timeout_seconds = tonumber(args.timeout) or DEFAULT_TIMEOUT_SECONDS
    if timeout_seconds <= 0 then timeout_seconds = DEFAULT_TIMEOUT_SECONDS end
    local timeout_ms = math.floor(timeout_seconds * 1000)

    local session
    local connect
    local request

    local function cleanup()
        close_handle(request)
        close_handle(connect)
        close_handle(session)
        request, connect, session = nil, nil, nil
    end

    local user_agent = tostring(args.user_agent or DEFAULT_USER_AGENT)
    local user_agent_w = to_wide(user_agent)
    if not user_agent_w then
        return nil, make_error('encoding', 0, 'HTTP_ENCODING', 'Unable to encode User-Agent')
    end

    session = winhttp.WinHttpOpen(user_agent_w, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nil, nil, 0)
    if is_null(session) then
        session = winhttp.WinHttpOpen(user_agent_w, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0)
    end
    if is_null(session) then
        local err = last_error('open_session')
        cleanup()
        return nil, err
    end

    winhttp.WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms)

    local http_protocols = ffi.new('unsigned long[1]', WINHTTP_PROTOCOL_FLAG_HTTP2)
    winhttp.WinHttpSetOption(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, http_protocols, ffi.sizeof(http_protocols))

    local host_w = to_wide(parsed.host)
    if not host_w then
        cleanup()
        return nil, make_error('encoding', 0, 'HTTP_ENCODING', 'Unable to encode host')
    end

    connect = winhttp.WinHttpConnect(session, host_w, parsed.port, 0)
    if is_null(connect) then
        local err = last_error('connect', nil, { host = parsed.host, port = parsed.port })
        cleanup()
        return nil, err
    end

    local method_w = to_wide(method)
    local target_w = to_wide(parsed.target)
    if not method_w or not target_w then
        cleanup()
        return nil, make_error('encoding', 0, 'HTTP_ENCODING', 'Unable to encode request method or target')
    end

    local flags = parsed.secure and WINHTTP_FLAG_SECURE or 0
    request = winhttp.WinHttpOpenRequest(connect, method_w, target_w, nil, nil, nil, flags)
    if is_null(request) then
        local err = last_error('open_request')
        cleanup()
        return nil, err
    end

    winhttp.WinHttpSetTimeouts(request, timeout_ms, timeout_ms, timeout_ms, timeout_ms)

    local fast_fallback = ffi.new('int[1]', 1)
    winhttp.WinHttpSetOption(request, WINHTTP_OPTION_IPV6_FAST_FALLBACK, fast_fallback, ffi.sizeof(fast_fallback))

    local decompression = ffi.new('unsigned long[1]', bit.bor(WINHTTP_DECOMPRESSION_FLAG_GZIP, WINHTTP_DECOMPRESSION_FLAG_DEFLATE))
    winhttp.WinHttpSetOption(request, WINHTTP_OPTION_DECOMPRESSION, decompression, ffi.sizeof(decompression))

    local header_block = build_headers(args.headers, user_agent)
    local header_w, header_chars
    if header_block then header_w, header_chars = to_wide(header_block) end
    if header_block and not header_w then
        cleanup()
        return nil, make_error('encoding', 0, 'HTTP_ENCODING', 'Unable to encode request headers')
    end

    local body = args.data
    if body == nil then body = '' end
    if type(body) ~= 'string' then body = tostring(body) end
    local body_ptr = #body > 0 and ffi.cast('const char*', body) or nil

    local sent = winhttp.WinHttpSendRequest(
        request,
        header_w,
        header_w and (header_chars or 0) or 0,
        body_ptr,
        #body,
        #body,
        0
    )
    if sent == 0 then
        local err = last_error('send', nil, { host = parsed.host, port = parsed.port })
        cleanup()
        return nil, err
    end

    if winhttp.WinHttpReceiveResponse(request, nil) == 0 then
        local err = last_error('receive', nil, { host = parsed.host, port = parsed.port })
        cleanup()
        return nil, err
    end

    local status_code, status_err = query_status_code(request)
    if not status_code then
        cleanup()
        return nil, status_err
    end

    local raw_headers = query_raw_headers(request)
    local response_headers = parse_raw_headers(raw_headers)
    local body_text, read_err = read_body(request, args.max_body_size)
    if body_text == nil then
        cleanup()
        return nil, read_err
    end

    cleanup()

    return {
        status_code = status_code,
        status = 'HTTP ' .. tostring(status_code),
        headers = response_headers,
        text = body_text,
        content = body_text,
        url = tostring(url),
        backend = M.backend
    }
end

local function write_file_atomic(path, data)
    path = tostring(path or '')
    if path == '' then
        return nil, make_error('file', 0, 'HTTP_FILE', 'Destination path is empty')
    end

    local suffix = string.format('.pm_download_%d_%06d.tmp', os.time(), math.random(0, 999999))
    local temp_path = path .. suffix
    local file, open_err = io.open(temp_path, 'wb')
    if not file then
        return nil, make_error('file', 0, 'HTTP_FILE', tostring(open_err or 'Unable to open temporary file'))
    end

    local ok_write, write_err = pcall(function()
        file:write(data)
        file:flush()
        file:close()
    end)
    if not ok_write then
        pcall(function() file:close() end)
        os.remove(temp_path)
        return nil, make_error('file', 0, 'HTTP_FILE', tostring(write_err or 'Unable to write file'))
    end

    local temp_w = to_wide_path(temp_path)
    local path_w = to_wide_path(path)
    if not temp_w or not path_w then
        os.remove(temp_path)
        return nil, make_error('file', 0, 'HTTP_ENCODING', 'Unable to encode destination path')
    end

    local moved = kernel32.MoveFileExW(temp_w, path_w, bit.bor(MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH))
    if moved == 0 then
        local err = last_error('file_move', 'HTTP_FILE')
        kernel32.DeleteFileW(temp_w)
        return nil, err
    end

    return true
end

function M.download(url, path, args)
    args = args or {}
    local response, err = M.request(args.method or 'GET', url, args)
    if not response then return nil, err end
    if response.status_code < 200 or response.status_code >= 300 then
        return nil, make_error('http_status', 0, 'HTTP_STATUS', 'HTTP ' .. tostring(response.status_code), {
            status = response.status_code,
            url = tostring(url)
        })
    end

    local ok, file_err = write_file_atomic(path, response.text or '')
    if not ok then return nil, file_err end

    response.saved_to = tostring(path)
    response.bytes = #(response.text or '')
    if args.keep_body ~= true then
        response.text = ''
        response.content = ''
    end
    return response
end

function M.info()
    return {
        version = M._VERSION,
        backend = M.backend,
        tls = 'Windows Schannel',
        async_model = 'Designed to run inside Price Monitor effil workers'
    }
end

return M
