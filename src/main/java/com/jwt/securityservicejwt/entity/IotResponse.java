package com.jwt.securityservicejwt.entity;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class IotResponse<T> {

    private T message;

    private int httpStatusCode;

    private Boolean isSuccess;

}
