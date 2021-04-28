package foundation.identity.keri.api;

public interface Version {

  Version CURRENT = new Version() {

    @Override
    public int major() {
      return 1;
    }

    @Override
    public int minor() {
      return 0;
    }

    public String toString() {
      return this.major() + "." + this.minor();
    }

  };

  int major();

  int minor();

}
