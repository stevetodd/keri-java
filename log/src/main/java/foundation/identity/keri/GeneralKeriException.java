package foundation.identity.keri;

import java.io.Serial;

public class GeneralKeriException extends RuntimeException {
  @Serial
  private static final long serialVersionUID = 1L;

  public GeneralKeriException() {
    super();
  }

  public GeneralKeriException(String message) {
    super(message);
  }

  public GeneralKeriException(String message, Throwable cause) {
    super(message, cause);
  }

  public GeneralKeriException(Throwable cause) {
    super(cause);
  }

}
