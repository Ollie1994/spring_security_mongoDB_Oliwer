package se.java.security.exceptions;

public class UnauthorizedException extends RuntimeException{
  public UnauthorizedException(String message) {
    super(message);
  }
}