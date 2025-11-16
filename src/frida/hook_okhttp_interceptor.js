/**
 * OkHttp Interceptor Hooking Script
 * 목적: OkHttp 레벨에서 모든 HTTP 요청/응답 인터셉트
 * 작성일: 2025-01-15
 * 에이전트: Reverse Engineer
 */

Java.perform(function() {
    console.log("[+] OkHttp Interceptor Hook Started");
    console.log("[+] Targeting Naver Shopping API traffic...\n");

    // OkHttp3 Interceptor 후킹
    try {
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Request = Java.use("okhttp3.Request");
        var Response = Java.use("okhttp3.Response");
        var RequestBody = Java.use("okhttp3.RequestBody");
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        var Headers = Java.use("okhttp3.Headers");
        var Buffer = Java.use("okio.Buffer");

        console.log("[+] OkHttp3 classes loaded successfully");

        // Interceptor.intercept() 후킹
        Interceptor.intercept.overload('okhttp3.Interceptor$Chain').implementation = function(chain) {
            var request = chain.request();
            var url = request.url().toString();

            // 네이버 도메인만 필터링
            if (url.indexOf("naver.com") !== -1 || url.indexOf("shopping") !== -1) {
                var timestamp = new Date().toISOString();
                var logData = {
                    timestamp: timestamp,
                    type: "HTTP_REQUEST",
                    url: url,
                    method: request.method(),
                    headers: {},
                    body: null
                };

                // Headers 추출
                var headers = request.headers();
                var headerNames = headers.names();
                var headerIterator = headerNames.iterator();
                while (headerIterator.hasNext()) {
                    var name = headerIterator.next();
                    var value = headers.get(name);
                    logData.headers[name] = value;
                }

                // Request Body 추출
                try {
                    var requestBody = request.body();
                    if (requestBody !== null) {
                        var buffer = Buffer.$new();
                        requestBody.writeTo(buffer);
                        var bodyString = buffer.readUtf8();
                        buffer.close();

                        // JSON 파싱 시도
                        try {
                            logData.body = JSON.parse(bodyString);
                        } catch (e) {
                            logData.body = bodyString;
                        }
                    }
                } catch (e) {
                    logData.body_error = e.toString();
                }

                console.log("[REQUEST] " + JSON.stringify(logData, null, 2));
            }

            // 실제 요청 실행
            var response = this.intercept(chain);

            // Response 로깅
            if (url.indexOf("naver.com") !== -1 || url.indexOf("shopping") !== -1) {
                var timestamp = new Date().toISOString();
                var logData = {
                    timestamp: timestamp,
                    type: "HTTP_RESPONSE",
                    url: url,
                    status_code: response.code(),
                    status_message: response.message(),
                    headers: {},
                    body: null
                };

                // Response Headers 추출
                var headers = response.headers();
                var headerNames = headers.names();
                var headerIterator = headerNames.iterator();
                while (headerIterator.hasNext()) {
                    var name = headerIterator.next();
                    var value = headers.get(name);
                    logData.headers[name] = value;
                }

                // Response Body 추출
                try {
                    var responseBody = response.body();
                    if (responseBody !== null) {
                        var source = responseBody.source();
                        source.request(Java.use("java.lang.Long").MAX_VALUE.value);
                        var buffer = source.buffer();
                        var bodyString = buffer.clone().readUtf8();

                        // JSON 파싱 시도
                        try {
                            logData.body = JSON.parse(bodyString);
                        } catch (e) {
                            logData.body = bodyString.substring(0, 500); // 최대 500자만
                        }
                    }
                } catch (e) {
                    logData.body_error = e.toString();
                }

                console.log("[RESPONSE] " + JSON.stringify(logData, null, 2));
            }

            return response;
        };

        console.log("[+] Interceptor.intercept() hooked successfully\n");

    } catch (e) {
        console.log("[-] Error hooking OkHttp Interceptor: " + e.toString());
    }

    // OkHttpClient.Builder 후킹 (추가 인터셉터 감지)
    try {
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");

        OkHttpClientBuilder.addInterceptor.overload('okhttp3.Interceptor').implementation = function(interceptor) {
            console.log("[+] Interceptor added: " + interceptor.$className);
            return this.addInterceptor(interceptor);
        };

        OkHttpClientBuilder.addNetworkInterceptor.overload('okhttp3.Interceptor').implementation = function(interceptor) {
            console.log("[+] Network Interceptor added: " + interceptor.$className);
            return this.addNetworkInterceptor(interceptor);
        };

        console.log("[+] OkHttpClient.Builder hooked successfully\n");

    } catch (e) {
        console.log("[-] Error hooking OkHttpClient.Builder: " + e.toString());
    }

    console.log("[+] All OkHttp hooks installed successfully");
    console.log("[+] Waiting for HTTP traffic...\n");
});
