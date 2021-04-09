package foundation.identity.keri;

/**
 * Thrown by {@link KeyEventValidator} to indicate that an event being processed is not valid in
 * form or configuration.
 */
public class InvalidKeyEventException extends RuntimeException {

  public InvalidKeyEventException() {
    super();
  }

  public InvalidKeyEventException(String message) {
    super(message);
  }

  public InvalidKeyEventException(String message, Throwable cause) {
    super(message, cause);
  }

  public InvalidKeyEventException(Throwable cause) {
    super(cause);
  }

}
