package foundation.identity.keri.api.identifier;

public interface Identifier {

  Identifier NONE = new None();

  /**
   * @return if prefix type allows for rotation
   */
  boolean transferable();

  /**
   * Compares the specified object with this prefix for equality. Returns
   * {@code true} if and only if the specified prefix is of the same type and
   * has the same field values. Of note, different implementations of Prefix
   * interfaces should be equals. For example, two different implementations
   * of BasicPrefix should be equal if the value of primaryKey() is equal.
   *
   * @param o
   *     the object to be compared for equality with this prefix
   *
   * @return {@code true} if the specified object is equal to this prefix
   */
  boolean equals(Object o);

  /**
   * Returns the hash code for this prefix. The hash code of a prefix is
   * defined to be result of calling {@code Object.hash(...)} with each field
   * in the order they appear in the interface. This detail must be observed by
   * all implementations to ensure that hash codes are generated the same way
   * among all implementations.
   *
   * @return the hash code value for this prefix
   */
  int hashCode();

  class None implements Identifier {

    None() {
    }

    @Override
    public boolean transferable() {
      return false;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }

      if (obj == null) {
        return false;
      }

      return getClass() == obj.getClass();
    }

    @Override
    public int hashCode() {
      return 1;
    }

  }

}
