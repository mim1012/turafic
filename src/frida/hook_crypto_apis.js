/**
 * Crypto API Hooking Script
 * 목적: javax.crypto 및 java.security API 후킹하여 암호화/서명 연산 추적
 * 작성일: 2025-01-15
 * 에이전트: Reverse Engineer
 */

Java.perform(function() {
    console.log("[+] Crypto API Hook Started");
    console.log("[+] Targeting javax.crypto.Mac and java.security.MessageDigest...\n");

    // Byte Array를 Hex String으로 변환하는 헬퍼 함수
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

    // 스택 트레이스 추출 함수
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var stackTrace = Exception.$new().getStackTrace();
        var result = [];
        for (var i = 0; i < Math.min(stackTrace.length, 10); i++) {
            result.push(stackTrace[i].toString());
        }
        return result;
    }

    // javax.crypto.Mac 후킹
    try {
        var Mac = Java.use("javax.crypto.Mac");

        // Mac.init(Key) - Secret Key 추출
        Mac.init.overload('java.security.Key').implementation = function(key) {
            var timestamp = new Date().toISOString();
            var algorithm = this.getAlgorithm();

            var logData = {
                timestamp: timestamp,
                type: "CRYPTO_MAC_INIT",
                algorithm: algorithm,
                key_algorithm: null,
                key_format: null,
                key_encoded: null,
                stack_trace: getStackTrace()
            };

            try {
                logData.key_algorithm = key.getAlgorithm();
                logData.key_format = key.getFormat();
                var encoded = key.getEncoded();
                if (encoded !== null) {
                    logData.key_encoded = bytesToHex(encoded);
                }
            } catch (e) {
                logData.key_error = e.toString();
            }

            console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));

            return this.init(key);
        };

        // Mac.doFinal(byte[]) - 최종 서명 생성
        Mac.doFinal.overload('[B').implementation = function(input) {
            var timestamp = new Date().toISOString();
            var algorithm = this.getAlgorithm();
            var output = this.doFinal(input);

            var logData = {
                timestamp: timestamp,
                type: "CRYPTO_MAC_DOFINAL",
                algorithm: algorithm,
                input_hex: bytesToHex(input),
                input_length: input.length,
                input_utf8: null,
                output_hex: bytesToHex(output),
                output_length: output.length,
                stack_trace: getStackTrace()
            };

            // UTF-8로 디코딩 시도
            try {
                var String = Java.use("java.lang.String");
                logData.input_utf8 = String.$new(input, "UTF-8");
            } catch (e) {
                // Binary data일 경우 무시
            }

            console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));

            return output;
        };

        // Mac.update(byte[]) - 데이터 업데이트
        Mac.update.overload('[B').implementation = function(input) {
            var timestamp = new Date().toISOString();
            var algorithm = this.getAlgorithm();

            var logData = {
                timestamp: timestamp,
                type: "CRYPTO_MAC_UPDATE",
                algorithm: algorithm,
                input_hex: bytesToHex(input),
                input_length: input.length,
                input_utf8: null
            };

            // UTF-8로 디코딩 시도
            try {
                var String = Java.use("java.lang.String");
                logData.input_utf8 = String.$new(input, "UTF-8");
            } catch (e) {
                // Binary data일 경우 무시
            }

            console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));

            return this.update(input);
        };

        console.log("[+] javax.crypto.Mac hooked successfully");

    } catch (e) {
        console.log("[-] Error hooking javax.crypto.Mac: " + e.toString());
    }

    // java.security.MessageDigest 후킹
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");

        // MessageDigest.getInstance(String) - 알고리즘 확인
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("[+] MessageDigest.getInstance called with algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        // MessageDigest.digest(byte[]) - 해시 생성
        MessageDigest.digest.overload('[B').implementation = function(input) {
            var timestamp = new Date().toISOString();
            var algorithm = this.getAlgorithm();
            var output = this.digest(input);

            var logData = {
                timestamp: timestamp,
                type: "CRYPTO_DIGEST",
                algorithm: algorithm,
                input_hex: bytesToHex(input),
                input_length: input.length,
                input_utf8: null,
                output_hex: bytesToHex(output),
                output_length: output.length,
                stack_trace: getStackTrace()
            };

            // UTF-8로 디코딩 시도
            try {
                var String = Java.use("java.lang.String");
                logData.input_utf8 = String.$new(input, "UTF-8");
            } catch (e) {
                // Binary data일 경우 무시
            }

            console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));

            return output;
        };

        // MessageDigest.update(byte[]) - 데이터 업데이트
        MessageDigest.update.overload('[B').implementation = function(input) {
            var timestamp = new Date().toISOString();
            var algorithm = this.getAlgorithm();

            var logData = {
                timestamp: timestamp,
                type: "CRYPTO_DIGEST_UPDATE",
                algorithm: algorithm,
                input_hex: bytesToHex(input),
                input_length: input.length,
                input_utf8: null
            };

            // UTF-8로 디코딩 시도
            try {
                var String = Java.use("java.lang.String");
                logData.input_utf8 = String.$new(input, "UTF-8");
            } catch (e) {
                // Binary data일 경우 무시
            }

            console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));

            return this.update(input);
        };

        console.log("[+] java.security.MessageDigest hooked successfully");

    } catch (e) {
        console.log("[-] Error hooking java.security.MessageDigest: " + e.toString());
    }

    // Base64 인코딩/디코딩 추적 (서명이 Base64로 인코딩될 수 있음)
    try {
        var Base64 = Java.use("android.util.Base64");

        // Base64.encodeToString
        Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
            var output = this.encodeToString(input, flags);

            // 서명 관련 데이터인지 확인 (길이 기반 휴리스틱)
            if (input.length >= 16) {
                var timestamp = new Date().toISOString();
                var logData = {
                    timestamp: timestamp,
                    type: "BASE64_ENCODE",
                    input_hex: bytesToHex(input),
                    input_length: input.length,
                    output: output,
                    flags: flags
                };

                console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));
            }

            return output;
        };

        // Base64.decode
        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            var output = this.decode(str, flags);

            // 서명 관련 데이터인지 확인
            if (output.length >= 16) {
                var timestamp = new Date().toISOString();
                var logData = {
                    timestamp: timestamp,
                    type: "BASE64_DECODE",
                    input: str,
                    output_hex: bytesToHex(output),
                    output_length: output.length,
                    flags: flags
                };

                console.log("[CRYPTO] " + JSON.stringify(logData, null, 2));
            }

            return output;
        };

        console.log("[+] android.util.Base64 hooked successfully");

    } catch (e) {
        console.log("[-] Error hooking android.util.Base64: " + e.toString());
    }

    console.log("[+] All Crypto API hooks installed successfully");
    console.log("[+] Waiting for crypto operations...\n");
});
