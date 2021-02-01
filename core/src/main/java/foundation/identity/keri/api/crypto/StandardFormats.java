package foundation.identity.keri.api.crypto;

import foundation.identity.keri.api.event.Format;

public enum StandardFormats implements Format {
  JSON,
  MESSAGE_PACK,
  CBOR;

  public static StandardFormats lookup(String formatName) {
    for (var v : values()) {
      if (v.formatName().equals(formatName)) {
        return v;
      }
    }

    throw new IllegalArgumentException("Unknown format: " + formatName);
  }

  @Override
  public String formatName() {
    return this.name();
  }

}
