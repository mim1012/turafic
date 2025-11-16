/**
 * Signature Functions Hooking Script
 * 목적: 커스텀 서명 함수 (HttpEngine.genHeader, x-wtm-graphql 생성 등) 후킹
 * 작성일: 2025-01-15
 * 에이전트: Reverse Engineer
 */

Java.perform(function() {
    console.log("[+] Signature Functions Hook Started");
    console.log("[+] Searching for custom signature generation functions...\n");

    // Byte Array를 Hex String으로 변환
    function bytesToHex(bytes) {
        if (bytes === null) return null;
        var hexArray = [];
        for (var i = 0; i < bytes.length; i++) {
            var hex = (bytes[i] & 0xFF).toString(16);
            if (hex.length === 1) hex = '0' + hex;
            hexArray.push(hex);
        }
        return hexArray.join('');
    }

    // 스택 트레이스 추출
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var stackTrace = Exception.$new().getStackTrace();
        var result = [];
        for (var i = 0; i < Math.min(stackTrace.length, 15); i++) {
            result.push(stackTrace[i].toString());
        }
        return result;
    }

    // 서명 관련 클래스명 패턴
    var signatureClassPatterns = [
        "HttpEngine",
        "HeaderBuilder",
        "SignatureBuilder",
        "SignatureGenerator",
        "WtmSignature",
        "NaverSignature",
        "RequestSigner",
        "SecurityUtil",
        "CryptoUtil"
    ];

    // 서명 관련 메서드명 패턴
    var signatureMethodPatterns = [
        "genHeader",
        "generateHeader",
        "buildHeader",
        "createSignature",
        "generateSignature",
        "sign",
        "wtmSign",
        "graphqlSign",
        "calculateSignature",
        "makeSignature"
    ];

    // 클래스 검색 및 후킹
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // 서명 관련 클래스 패턴 매칭
            var isSignatureClass = false;
            for (var i = 0; i < signatureClassPatterns.length; i++) {
                if (className.indexOf(signatureClassPatterns[i]) !== -1) {
                    isSignatureClass = true;
                    break;
                }
            }

            if (isSignatureClass) {
                console.log("[+] Found signature-related class: " + className);

                try {
                    var SignatureClass = Java.use(className);

                    // 클래스의 모든 메서드 나열
                    var methods = SignatureClass.class.getDeclaredMethods();
                    console.log("[+] Methods in " + className + ":");

                    for (var j = 0; j < methods.length; j++) {
                        var method = methods[j];
                        var methodName = method.getName();

                        console.log("  [+] " + methodName);

                        // 서명 관련 메서드인지 확인
                        var isSignatureMethod = false;
                        for (var k = 0; k < signatureMethodPatterns.length; k++) {
                            if (methodName.toLowerCase().indexOf(signatureMethodPatterns[k].toLowerCase()) !== -1) {
                                isSignatureMethod = true;
                                break;
                            }
                        }

                        // 서명 관련 메서드 후킹
                        if (isSignatureMethod) {
                            console.log("    [+] Signature method detected: " + methodName);

                            try {
                                var targetMethod = SignatureClass[methodName];
                                if (targetMethod && targetMethod.overloads) {
                                    for (var l = 0; l < targetMethod.overloads.length; l++) {
                                        targetMethod.overloads[l].implementation = function() {
                                            var timestamp = new Date().toISOString();
                                            var logData = {
                                                timestamp: timestamp,
                                                type: "SIGNATURE_FUNCTION",
                                                class: className,
                                                method: methodName,
                                                arguments: [],
                                                stack_trace: getStackTrace()
                                            };

                                            // 인자 로깅
                                            for (var m = 0; m < arguments.length; m++) {
                                                var arg = arguments[m];
                                                var argLog = {
                                                    index: m,
                                                    type: null,
                                                    value: null,
                                                    value_hex: null
                                                };

                                                try {
                                                    if (arg === null) {
                                                        argLog.type = "null";
                                                        argLog.value = null;
                                                    } else if (arg.$className) {
                                                        argLog.type = arg.$className;

                                                        // byte[] 타입인 경우 hex로 변환
                                                        if (arg.$className === "[B" || arg instanceof Array) {
                                                            argLog.value_hex = bytesToHex(arg);
                                                            // UTF-8 디코딩 시도
                                                            try {
                                                                var String = Java.use("java.lang.String");
                                                                argLog.value = String.$new(arg, "UTF-8");
                                                            } catch (e) {
                                                                argLog.value = "[Binary data]";
                                                            }
                                                        } else {
                                                            argLog.value = arg.toString();
                                                        }
                                                    } else {
                                                        argLog.type = typeof arg;
                                                        argLog.value = arg.toString();
                                                    }
                                                } catch (e) {
                                                    argLog.error = e.toString();
                                                }

                                                logData.arguments.push(argLog);
                                            }

                                            console.log("[SIGNATURE] " + JSON.stringify(logData, null, 2));

                                            // 원본 메서드 호출
                                            var result = this[methodName].apply(this, arguments);

                                            // 결과 로깅
                                            var resultLog = {
                                                timestamp: new Date().toISOString(),
                                                type: "SIGNATURE_RESULT",
                                                class: className,
                                                method: methodName,
                                                result: null,
                                                result_hex: null
                                            };

                                            try {
                                                if (result === null) {
                                                    resultLog.result = null;
                                                } else if (result.$className) {
                                                    resultLog.result_type = result.$className;

                                                    // byte[] 타입인 경우
                                                    if (result.$className === "[B" || result instanceof Array) {
                                                        resultLog.result_hex = bytesToHex(result);
                                                        try {
                                                            var String = Java.use("java.lang.String");
                                                            resultLog.result = String.$new(result, "UTF-8");
                                                        } catch (e) {
                                                            resultLog.result = "[Binary data]";
                                                        }
                                                    } else {
                                                        resultLog.result = result.toString();
                                                    }
                                                } else {
                                                    resultLog.result = result.toString();
                                                }
                                            } catch (e) {
                                                resultLog.error = e.toString();
                                            }

                                            console.log("[SIGNATURE_RESULT] " + JSON.stringify(resultLog, null, 2));

                                            return result;
                                        };
                                    }
                                    console.log("    [+] Hooked: " + methodName);
                                }
                            } catch (e) {
                                console.log("    [-] Error hooking method " + methodName + ": " + e.toString());
                            }
                        }
                    }

                } catch (e) {
                    console.log("[-] Error processing class " + className + ": " + e.toString());
                }
            }
        },
        onComplete: function() {
            console.log("[+] Signature class enumeration complete\n");
        }
    });

    // 문자열 연결 패턴 감지 (서명 base string 구성)
    // "timestamp" + "loginId" + "body" 같은 패턴
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");

        var originalToString = StringBuilder.toString;

        StringBuilder.toString.implementation = function() {
            var result = originalToString.call(this);

            // 서명 관련 키워드가 포함된 경우 (timestamp, login_id, sus_val, wtm 등)
            if (result && (
                result.indexOf("timestamp") !== -1 ||
                result.indexOf("login_id") !== -1 ||
                result.indexOf("sus_val") !== -1 ||
                result.indexOf("wtm") !== -1 ||
                result.indexOf("graphql") !== -1
            )) {
                var timestamp = new Date().toISOString();
                console.log("[SIGNATURE_BASE_STRING] Detected at " + timestamp + ":");
                console.log(result.substring(0, 500));
            }

            return result;
        };

        console.log("[+] StringBuilder.toString() hooked for base string detection");

    } catch (e) {
        console.log("[-] Error hooking StringBuilder: " + e.toString());
    }

    // String.format 후킹 (서명 템플릿 감지)
    try {
        var String = Java.use("java.lang.String");

        String.format.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(format, args) {
            var result = this.format(format, args);

            // 서명 관련 포맷 문자열 감지
            if (format && (
                format.indexOf("%s") !== -1 &&
                (format.indexOf("timestamp") !== -1 || format.indexOf("sign") !== -1)
            )) {
                var timestamp = new Date().toISOString();
                console.log("[SIGNATURE_FORMAT] Detected at " + timestamp + ":");
                console.log("Format: " + format);
                console.log("Result: " + result);
            }

            return result;
        };

        console.log("[+] String.format() hooked for signature template detection");

    } catch (e) {
        console.log("[-] Error hooking String.format: " + e.toString());
    }

    console.log("[+] All signature function hooks installed successfully");
    console.log("[+] Waiting for signature operations...\n");
});
