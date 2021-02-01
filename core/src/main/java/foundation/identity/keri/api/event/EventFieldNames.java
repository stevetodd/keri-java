package foundation.identity.keri.api.event;

import java.util.Arrays;
import java.util.EnumSet;

public enum EventFieldNames {
  VERSION("v"),
  IDENTIFIER("i"),
  SEQUENCE_NUMBER("s"),
  EVENT_TYPE("t"),
  PRIOR_EVENT_DIGEST("p"),
  EVENT_DIGEST("d"),
  SIGNING_THRESHOLD("kt"),
  KEYS("k"),
  NEXT_KEYS_DIGEST("n"),
  WITNESS_THRESHOLD("wt"),
  WITNESSES("w"),
  WITNESSES_REMOVED("wr"),
  WITNESSES_ADDED("wa"),
  CONFIGURATION("c"),
  ANCHORS("a"),
  DELEGATOR_ANCHOR("da");

  public static final EnumSet<EventFieldNames> INCEPTION_FIELDS;
  public static final EnumSet<EventFieldNames> ROTATION_FIELDS;
  public static final EnumSet<EventFieldNames> INTERACTION_FIELDS;
  public static final EnumSet<EventFieldNames> DELEGATED_INCEPTION_FIELDS;
  public static final EnumSet<EventFieldNames> DELEGATED_ROTATION_FIELDS;

  public static final EnumSet<EventFieldNames> RECEIPT_NON_TRANSFERRABLE_IDENTIFIER;
  public static final EnumSet<EventFieldNames> RECEIPT_TRANSFERRABLE_IDENTIFIER;

  static {
    var headerFields = EnumSet.of(VERSION, IDENTIFIER, SEQUENCE_NUMBER, EVENT_TYPE);
    INCEPTION_FIELDS = withFields(headerFields, SIGNING_THRESHOLD, KEYS, NEXT_KEYS_DIGEST, WITNESS_THRESHOLD, WITNESSES,
        CONFIGURATION);
    ROTATION_FIELDS = withFields(headerFields, PRIOR_EVENT_DIGEST, SIGNING_THRESHOLD, KEYS, NEXT_KEYS_DIGEST,
        WITNESS_THRESHOLD, WITNESSES_REMOVED, WITNESSES_ADDED, ANCHORS);
    INTERACTION_FIELDS = withFields(headerFields, ANCHORS);
    DELEGATED_INCEPTION_FIELDS = withFields(INCEPTION_FIELDS, DELEGATOR_ANCHOR);
    DELEGATED_ROTATION_FIELDS = withFields(ROTATION_FIELDS, DELEGATOR_ANCHOR);
    RECEIPT_NON_TRANSFERRABLE_IDENTIFIER = withFields(headerFields, EVENT_DIGEST);
    RECEIPT_TRANSFERRABLE_IDENTIFIER = withFields(headerFields, EVENT_DIGEST, ANCHORS);
  }

  private final String label;

  EventFieldNames(String label) {
    this.label = label;
  }

  private static EnumSet<EventFieldNames> withFields(EnumSet<EventFieldNames> base, EventFieldNames... additonal) {
    var fields = EnumSet.copyOf(base);
    fields.addAll(Arrays.asList(additonal));
    return fields;
  }

  public String label() {
    return this.label;
  }
}
