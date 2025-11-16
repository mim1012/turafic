/**
 * DTO Classes Hooking Script
 * 목적: Zero 서버 응답 데이터를 담는 DTO 클래스 및 10개 변수 세트 추출
 * 작성일: 2025-01-15
 * 에이전트: Reverse Engineer
 */

Java.perform(function() {
    console.log("[+] DTO Classes Hook Started");
    console.log("[+] Searching for KeywordItem, TaskItem, WorkConfig classes...\n");

    // 공통 DTO 필드 로깅 함수
    function logDtoFields(obj, className) {
        var timestamp = new Date().toISOString();
        var logData = {
            timestamp: timestamp,
            type: "DTO_FIELDS",
            class_name: className,
            fields: {}
        };

        try {
            var clazz = obj.getClass();
            var fields = clazz.getDeclaredFields();

            for (var i = 0; i < fields.length; i++) {
                var field = fields[i];
                field.setAccessible(true);
                var fieldName = field.getName();
                var fieldValue = null;

                try {
                    fieldValue = field.get(obj);
                    if (fieldValue !== null) {
                        fieldValue = fieldValue.toString();
                    }
                } catch (e) {
                    fieldValue = "[Error: " + e.toString() + "]";
                }

                logData.fields[fieldName] = fieldValue;
            }

            console.log("[DTO] " + JSON.stringify(logData, null, 2));
        } catch (e) {
            console.log("[-] Error logging DTO fields: " + e.toString());
        }
    }

    // 10개 변수 세트를 담을 가능성이 있는 클래스명 패턴
    var targetClassPatterns = [
        "KeywordItem",
        "TaskItem",
        "WorkConfig",
        "TrafficConfig",
        "ShoppingConfig",
        "AutomationConfig",
        "ZeroKeyword",
        "NaverKeyword"
    ];

    // Java.enumerateLoadedClasses로 모든 로드된 클래스 검색
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Zero 관련 패키지 또는 타겟 클래스 패턴 매칭
            if (className.indexOf("zero") !== -1 || className.indexOf("keyword") !== -1 || className.indexOf("task") !== -1) {
                for (var i = 0; i < targetClassPatterns.length; i++) {
                    if (className.indexOf(targetClassPatterns[i]) !== -1) {
                        console.log("[+] Found potential DTO class: " + className);

                        try {
                            var TargetClass = Java.use(className);

                            // 생성자 후킹
                            var constructors = TargetClass.class.getDeclaredConstructors();
                            for (var j = 0; j < constructors.length; j++) {
                                try {
                                    TargetClass.$init.overload.apply(TargetClass.$init, constructors[j].getParameterTypes()).implementation = function() {
                                        var result = this.$init.apply(this, arguments);
                                        console.log("[+] DTO Instance Created: " + className);
                                        logDtoFields(this, className);
                                        return result;
                                    };
                                } catch (e) {
                                    // 오버로드 실패 시 무시
                                }
                            }

                            console.log("[+] Hooked class: " + className);
                        } catch (e) {
                            console.log("[-] Error hooking class " + className + ": " + e.toString());
                        }
                    }
                }
            }
        },
        onComplete: function() {
            console.log("[+] Class enumeration complete");
        }
    });

    // 특정 필드명으로 10개 변수 직접 추적
    var targetFieldNames = [
        "ua_change",
        "cookie_home_mode",
        "shop_home",
        "use_nid",
        "use_image",
        "work_type",
        "random_click_count",
        "work_more",
        "sec_fetch_site_mode",
        "low_delay"
    ];

    console.log("[+] Monitoring for 10 variable set fields: " + targetFieldNames.join(", "));

    // Gson/Jackson 등 JSON 파싱 라이브러리 후킹 (DTO 자동 생성 감지)
    try {
        var Gson = Java.use("com.google.gson.Gson");

        Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function(json, classOfT) {
            var result = this.fromJson(json, classOfT);

            // JSON에 타겟 필드가 포함되어 있는지 확인
            var containsTargetField = false;
            for (var i = 0; i < targetFieldNames.length; i++) {
                if (json.indexOf(targetFieldNames[i]) !== -1) {
                    containsTargetField = true;
                    break;
                }
            }

            if (containsTargetField) {
                console.log("[+] Gson.fromJson detected 10-variable set!");
                console.log("[+] JSON: " + json);
                console.log("[+] Target Class: " + classOfT.toString());
                if (result !== null) {
                    logDtoFields(result, classOfT.getName());
                }
            }

            return result;
        };

        console.log("[+] Gson.fromJson() hooked successfully");

    } catch (e) {
        console.log("[-] Gson not found or error: " + e.toString());
    }

    // Jackson ObjectMapper 후킹
    try {
        var ObjectMapper = Java.use("com.fasterxml.jackson.databind.ObjectMapper");

        ObjectMapper.readValue.overload('java.lang.String', 'java.lang.Class').implementation = function(content, valueType) {
            var result = this.readValue(content, valueType);

            // JSON에 타겟 필드가 포함되어 있는지 확인
            var containsTargetField = false;
            for (var i = 0; i < targetFieldNames.length; i++) {
                if (content.indexOf(targetFieldNames[i]) !== -1) {
                    containsTargetField = true;
                    break;
                }
            }

            if (containsTargetField) {
                console.log("[+] Jackson.readValue detected 10-variable set!");
                console.log("[+] JSON: " + content);
                console.log("[+] Target Class: " + valueType.toString());
                if (result !== null) {
                    logDtoFields(result, valueType.getName());
                }
            }

            return result;
        };

        console.log("[+] Jackson ObjectMapper.readValue() hooked successfully");

    } catch (e) {
        console.log("[-] Jackson not found or error: " + e.toString());
    }

    console.log("[+] All DTO hooks installed successfully");
    console.log("[+] Waiting for DTO instantiation...\n");
});
