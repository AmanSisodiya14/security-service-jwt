package com.jwt.securityservicejwt.exception;

import com.jwt.securityservicejwt.entity.IotResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

@ControllerAdvice
public class IotExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<IotResponse<?>> handleResponseStatusException(ResponseStatusException exception) {
        HttpStatus status = (HttpStatus) exception.getStatusCode();
        String message = exception.getReason();

        IotResponse<?> response = new IotResponse<>(message, status.value(), false);

        return ResponseEntity
                .status(status)
                .header("Content-Type", "application/json")
                .body(response);
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception exception) {
        return new ResponseEntity<>(new IotResponse<>(exception.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(), false), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
