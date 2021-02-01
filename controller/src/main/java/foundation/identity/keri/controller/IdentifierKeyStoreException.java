package foundation.identity.keri.controller;

import foundation.identity.keri.GeneralKeriException;

import java.io.Serial;

public class IdentifierKeyStoreException extends GeneralKeriException {
  @Serial
  private static final long serialVersionUID = 1L;

  public IdentifierKeyStoreException() {
    super();
  }

  public IdentifierKeyStoreException(String message) {
    super(message);
  }

  public IdentifierKeyStoreException(String message, Throwable cause) {
    super(message, cause);
  }

  public IdentifierKeyStoreException(Throwable cause) {
    super(cause);
  }

}
