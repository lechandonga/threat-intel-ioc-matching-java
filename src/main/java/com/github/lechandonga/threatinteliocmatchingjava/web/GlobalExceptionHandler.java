package com.github.lechandonga.threatinteliocmatchingjava.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

/**
 * 请求体级别的错误（如 JSON 损坏）以 400 返回明确原因；
 * 记录级别的错误仍在正常响应体中逐条给出。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> badRequest(HttpMessageNotReadableException e) {
        return Map.of(
                "error", "MALFORMED_REQUEST_BODY",
                "message", e.getMostSpecificCause().getMessage() == null
                        ? "request body is not readable"
                        : e.getMostSpecificCause().getMessage(),
                "timestamp", Instant.now().toString());
    }
}
