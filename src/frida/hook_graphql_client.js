/**
 * GraphQL Client Hooking Script
 * 목적: 네이버 쇼핑 GraphQL API 요청/응답 및 x-wtm-graphql 서명 헤더 분석
 * 작성일: 2025-01-15
 * 에이전트: Reverse Engineer
 */

Java.perform(function() {
    console.log("[+] GraphQL Client Hook Started");
    console.log("[+] Targeting msearch.shopping.naver.com/api/graphql...\n");

    // GraphQL 관련 클래스 패턴 검색
    var graphqlClassPatterns = [
        "GraphQL",
        "GraphqlClient",
        "GraphQlClient",
        "GraphqlRequest",
        "GraphqlQuery"
    ];

    // 클래스 검색 및 후킹
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            for (var i = 0; i < graphqlClassPatterns.length; i++) {
                if (className.indexOf(graphqlClassPatterns[i]) !== -1) {
                    console.log("[+] Found GraphQL-related class: " + className);

                    try {
                        var GraphqlClass = Java.use(className);

                        // 클래스의 모든 메서드 나열
                        var methods = GraphqlClass.class.getDeclaredMethods();
                        for (var j = 0; j < methods.length; j++) {
                            var methodName = methods[j].getName();
                            console.log("  [+] Method: " + methodName);
                        }

                        // buildRequest, createRequest, execute 등 주요 메서드 후킹 시도
                        var targetMethods = ["buildRequest", "createRequest", "execute", "query", "mutate", "buildRequestBody", "buildHeaders"];

                        for (var k = 0; k < targetMethods.length; k++) {
                            try {
                                var targetMethod = targetMethods[k];
                                if (GraphqlClass[targetMethod]) {
                                    var overloads = GraphqlClass[targetMethod].overloads;
                                    for (var l = 0; l < overloads.length; l++) {
                                        overloads[l].implementation = function() {
                                            var timestamp = new Date().toISOString();
                                            console.log("[GRAPHQL] Method called: " + targetMethod + " at " + timestamp);
                                            console.log("[GRAPHQL] Arguments: " + JSON.stringify(arguments));

                                            var result = this[targetMethod].apply(this, arguments);

                                            console.log("[GRAPHQL] Result: " + JSON.stringify(result));

                                            return result;
                                        };
                                    }
                                    console.log("  [+] Hooked method: " + targetMethod);
                                }
                            } catch (e) {
                                // 메서드가 없거나 후킹 실패 시 무시
                            }
                        }

                    } catch (e) {
                        console.log("[-] Error processing class " + className + ": " + e.toString());
                    }
                }
            }
        },
        onComplete: function() {
            console.log("[+] GraphQL class enumeration complete");
        }
    });

    // x-wtm-graphql 헤더 생성 함수 추적
    // 일반적으로 HttpEngine, HeaderBuilder 등의 클래스에 있을 가능성
    var headerBuilderPatterns = [
        "HttpEngine",
        "HeaderBuilder",
        "RequestBuilder",
        "WtmHeader",
        "SignatureBuilder"
    ];

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            for (var i = 0; i < headerBuilderPatterns.length; i++) {
                if (className.indexOf(headerBuilderPatterns[i]) !== -1) {
                    console.log("[+] Found Header Builder class: " + className);

                    try {
                        var HeaderClass = Java.use(className);

                        // 모든 메서드 나열
                        var methods = HeaderClass.class.getDeclaredMethods();
                        for (var j = 0; j < methods.length; j++) {
                            var methodName = methods[j].getName();

                            // genHeader, buildHeader, createSignature 등 서명 관련 메서드 찾기
                            if (methodName.toLowerCase().indexOf("header") !== -1 ||
                                methodName.toLowerCase().indexOf("signature") !== -1 ||
                                methodName.toLowerCase().indexOf("wtm") !== -1 ||
                                methodName.toLowerCase().indexOf("sign") !== -1) {

                                console.log("  [+] Signature-related method found: " + methodName);

                                try {
                                    // 메서드 후킹
                                    var method = HeaderClass[methodName];
                                    if (method && method.overloads) {
                                        for (var k = 0; k < method.overloads.length; k++) {
                                            method.overloads[k].implementation = function() {
                                                var timestamp = new Date().toISOString();
                                                var logData = {
                                                    timestamp: timestamp,
                                                    type: "GRAPHQL_SIGNATURE",
                                                    method: methodName,
                                                    class: className,
                                                    arguments: []
                                                };

                                                // 인자 로깅
                                                for (var m = 0; m < arguments.length; m++) {
                                                    try {
                                                        logData.arguments.push(arguments[m].toString());
                                                    } catch (e) {
                                                        logData.arguments.push("[Object]");
                                                    }
                                                }

                                                var result = this[methodName].apply(this, arguments);

                                                logData.result = result !== null ? result.toString() : null;

                                                console.log("[GRAPHQL_SIG] " + JSON.stringify(logData, null, 2));

                                                return result;
                                            };
                                        }
                                        console.log("  [+] Hooked method: " + methodName);
                                    }
                                } catch (e) {
                                    console.log("  [-] Error hooking method " + methodName + ": " + e.toString());
                                }
                            }
                        }

                    } catch (e) {
                        console.log("[-] Error processing class " + className + ": " + e.toString());
                    }
                }
            }
        },
        onComplete: function() {
            console.log("[+] Header Builder class enumeration complete");
        }
    });

    // GraphQL 쿼리 문자열 추적 (쿼리 본문 확인)
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        var originalAppend = StringBuilder.append.overload('java.lang.String');

        StringBuilder.append.overload('java.lang.String').implementation = function(str) {
            // GraphQL 쿼리 패턴 감지
            if (str && (str.indexOf("query") === 0 || str.indexOf("mutation") === 0 || str.indexOf("fragment") === 0)) {
                var timestamp = new Date().toISOString();
                console.log("[GRAPHQL_QUERY] Detected at " + timestamp + ":");
                console.log(str);
            }

            return originalAppend.call(this, str);
        };

        console.log("[+] StringBuilder.append() hooked for GraphQL query detection");

    } catch (e) {
        console.log("[-] Error hooking StringBuilder: " + e.toString());
    }

    // GraphQL 응답 파싱 추적
    try {
        var JSONObject = Java.use("org.json.JSONObject");

        JSONObject.$init.overload('java.lang.String').implementation = function(json) {
            // GraphQL 응답 패턴 감지
            if (json && (json.indexOf('"data"') !== -1 || json.indexOf('"errors"') !== -1)) {
                var timestamp = new Date().toISOString();
                console.log("[GRAPHQL_RESPONSE] Detected at " + timestamp + ":");
                console.log(json.substring(0, 500)); // 첫 500자만 출력
            }

            return this.$init(json);
        };

        console.log("[+] JSONObject constructor hooked for GraphQL response detection");

    } catch (e) {
        console.log("[-] Error hooking JSONObject: " + e.toString());
    }

    console.log("[+] All GraphQL hooks installed successfully");
    console.log("[+] Waiting for GraphQL operations...\n");
});
