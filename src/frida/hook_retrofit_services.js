/**
 * Retrofit Services Hooking Script
 * 목적: Retrofit 서비스 인터페이스 및 API 메서드 호출 추적
 * 작성일: 2025-01-15
 * 에이전트: Reverse Engineer
 */

Java.perform(function() {
    console.log("[+] Retrofit Services Hook Started");
    console.log("[+] Searching for Retrofit service interfaces...\n");

    // Retrofit 관련 클래스
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");

        // Retrofit.create() - 서비스 인터페이스 생성 감지
        Retrofit.create.overload('java.lang.Class').implementation = function(serviceClass) {
            var timestamp = new Date().toISOString();
            var serviceName = serviceClass.getName();

            console.log("[RETROFIT] Service interface created at " + timestamp);
            console.log("[RETROFIT] Service class: " + serviceName);

            // 서비스 인터페이스의 모든 메서드 나열
            var methods = serviceClass.getDeclaredMethods();
            console.log("[RETROFIT] Methods in " + serviceName + ":");

            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                var returnType = method.getReturnType().getName();
                var paramTypes = method.getParameterTypes();

                var paramTypesStr = [];
                for (var j = 0; j < paramTypes.length; j++) {
                    paramTypesStr.push(paramTypes[j].getName());
                }

                console.log("  [+] " + returnType + " " + methodName + "(" + paramTypesStr.join(", ") + ")");

                // 어노테이션 추출
                var annotations = method.getAnnotations();
                for (var k = 0; k < annotations.length; k++) {
                    var annotation = annotations[k].toString();
                    console.log("      @" + annotation);
                }
            }

            var service = this.create(serviceClass);

            // 동적 프록시로 모든 메서드 호출 인터셉트
            try {
                var Proxy = Java.use("java.lang.reflect.Proxy");
                var InvocationHandler = Java.use("java.lang.reflect.InvocationHandler");

                var CustomHandler = Java.registerClass({
                    name: "com.frida.RetrofitInvocationHandler",
                    implements: [InvocationHandler],
                    methods: {
                        invoke: function(proxy, method, args) {
                            var timestamp = new Date().toISOString();
                            var methodName = method.getName();

                            var logData = {
                                timestamp: timestamp,
                                type: "RETROFIT_METHOD_CALL",
                                service: serviceName,
                                method: methodName,
                                arguments: []
                            };

                            // 인자 로깅
                            if (args !== null) {
                                for (var i = 0; i < args.length; i++) {
                                    try {
                                        var arg = args[i];
                                        if (arg !== null) {
                                            logData.arguments.push(arg.toString());
                                        } else {
                                            logData.arguments.push(null);
                                        }
                                    } catch (e) {
                                        logData.arguments.push("[Error: " + e.toString() + "]");
                                    }
                                }
                            }

                            console.log("[RETROFIT_CALL] " + JSON.stringify(logData, null, 2));

                            // 원본 메서드 호출
                            var result = method.invoke(service, args);

                            // 결과 로깅
                            try {
                                if (result !== null) {
                                    console.log("[RETROFIT_RESULT] " + result.toString());
                                }
                            } catch (e) {
                                console.log("[RETROFIT_RESULT] [Error: " + e.toString() + "]");
                            }

                            return result;
                        }
                    }
                });

                console.log("[+] Proxy handler registered for " + serviceName);

            } catch (e) {
                console.log("[-] Error creating proxy for service: " + e.toString());
            }

            return service;
        };

        console.log("[+] Retrofit.create() hooked successfully");

    } catch (e) {
        console.log("[-] Error hooking Retrofit: " + e.toString());
    }

    // Retrofit Call 실행 추적
    try {
        var Call = Java.use("retrofit2.Call");

        // Call.execute() - 동기 호출
        Call.execute.implementation = function() {
            var timestamp = new Date().toISOString();
            console.log("[RETROFIT] Call.execute() invoked at " + timestamp);

            var response = this.execute();

            try {
                console.log("[RETROFIT] Response code: " + response.code());
                console.log("[RETROFIT] Response message: " + response.message());

                var body = response.body();
                if (body !== null) {
                    console.log("[RETROFIT] Response body: " + body.toString().substring(0, 500));
                }
            } catch (e) {
                console.log("[-] Error reading response: " + e.toString());
            }

            return response;
        };

        // Call.enqueue() - 비동기 호출
        Call.enqueue.implementation = function(callback) {
            var timestamp = new Date().toISOString();
            console.log("[RETROFIT] Call.enqueue() invoked at " + timestamp);

            // Callback 래핑
            var Callback = Java.use("retrofit2.Callback");

            var originalCallback = callback;

            var CustomCallback = Java.registerClass({
                name: "com.frida.RetrofitCallbackWrapper",
                implements: [Callback],
                methods: {
                    onResponse: function(call, response) {
                        var timestamp = new Date().toISOString();
                        console.log("[RETROFIT] Callback.onResponse() at " + timestamp);

                        try {
                            console.log("[RETROFIT] Response code: " + response.code());
                            console.log("[RETROFIT] Response message: " + response.message());

                            var body = response.body();
                            if (body !== null) {
                                console.log("[RETROFIT] Response body: " + body.toString().substring(0, 500));
                            }
                        } catch (e) {
                            console.log("[-] Error reading response: " + e.toString());
                        }

                        // 원본 콜백 호출
                        originalCallback.onResponse(call, response);
                    },
                    onFailure: function(call, t) {
                        var timestamp = new Date().toISOString();
                        console.log("[RETROFIT] Callback.onFailure() at " + timestamp);
                        console.log("[RETROFIT] Error: " + t.toString());

                        // 원본 콜백 호출
                        originalCallback.onFailure(call, t);
                    }
                }
            });

            var wrappedCallback = CustomCallback.$new();

            return this.enqueue(wrappedCallback);
        };

        console.log("[+] retrofit2.Call hooked successfully");

    } catch (e) {
        console.log("[-] Error hooking retrofit2.Call: " + e.toString());
    }

    // Retrofit Converter (Gson, Jackson 등) 추적
    try {
        var GsonConverter = Java.use("retrofit2.converter.gson.GsonResponseBodyConverter");

        GsonConverter.convert.implementation = function(value) {
            var timestamp = new Date().toISOString();

            try {
                var bodyString = value.string();
                console.log("[RETROFIT_GSON] Converting response at " + timestamp + ":");
                console.log(bodyString.substring(0, 500));

                // 다시 ResponseBody 생성 (원본 데이터 복원)
                var MediaType = Java.use("okhttp3.MediaType");
                var ResponseBody = Java.use("okhttp3.ResponseBody");
                var recreatedBody = ResponseBody.create(MediaType.parse("application/json"), bodyString);

                return this.convert(recreatedBody);
            } catch (e) {
                console.log("[-] Error in GsonConverter: " + e.toString());
                return this.convert(value);
            }
        };

        console.log("[+] GsonResponseBodyConverter hooked successfully");

    } catch (e) {
        console.log("[-] GsonResponseBodyConverter not found or error: " + e.toString());
    }

    console.log("[+] All Retrofit hooks installed successfully");
    console.log("[+] Waiting for Retrofit API calls...\n");
});
