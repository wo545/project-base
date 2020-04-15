package com.shiyf.security.utils;

public class CommonResult<T> {
    private long code;
    private String message;
    private T data;

    public CommonResult(){}

    public CommonResult(long code,String message,T data){
        this.code = code;
        this.message = message;
        this.data = data;
    }
    public static <T> CommonResult<T> success(){
        return new CommonResult(ResultCode.SUCCESS.getCode(),ResultCode.SUCCESS.getMessage(),null);
    }
    public static <T> CommonResult<T> success(T data){
        return new CommonResult(ResultCode.SUCCESS.getCode(),ResultCode.SUCCESS.getMessage(),data);
    }
    public static <T> CommonResult<T> forbidden(T data){
        return new CommonResult(ResultCode.FORBIDDEN.getCode(),ResultCode.FORBIDDEN.getMessage(),data);
    }
    public static <T> CommonResult<T> unauthorized(T data){
        return new CommonResult(ResultCode.UNAUTHORIZED.getCode(),ResultCode.UNAUTHORIZED.getMessage(),data);
    }
    public static  CommonResult failed(long code,String message){
        return new CommonResult(code,message,null);
    }

    public String getMessage() {
        return message;
    }

    public long getCode() {
        return code;
    }

    public T getData() {
        return data;
    }

    public void setCode(long code) {
        this.code = code;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setData(T data) {
        this.data = data;
    }
}

