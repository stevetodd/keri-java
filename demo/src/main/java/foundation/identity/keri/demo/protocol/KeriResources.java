package foundation.identity.keri.demo.protocol;

import reactor.core.publisher.Mono;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;
import reactor.netty.tcp.TcpResources;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;

import static java.util.Objects.requireNonNull;

public class KeriResources extends TcpResources {

  public static void disposeLoopsAndConnections() {
    var resources = keriResources.getAndSet(null);
    if (resources != null) {
      resources._dispose();
    }
  }

  public static Mono<Void> disposeLoopsAndConnectionsLater() {
    return disposeLoopsAndConnectionsLater(Duration.ofSeconds(LoopResources.DEFAULT_SHUTDOWN_QUIET_PERIOD),
        Duration.ofSeconds(LoopResources.DEFAULT_SHUTDOWN_TIMEOUT));
  }

  public static Mono<Void> disposeLoopsAndConnectionsLater(Duration quietPeriod, Duration timeout) {
    requireNonNull(quietPeriod, "quietPeriod");
    requireNonNull(timeout, "timeout");
    return Mono.defer(() -> {
      var resources = keriResources.getAndSet(null);
      if (resources != null) {
        return resources._disposeLater(quietPeriod, timeout);
      }
      return Mono.empty();
    });
  }

  public static KeriResources get() {
    return getOrCreate(keriResources, null, null, ON_KERI_NEW, "keri");
  }

  public static KeriResources reset() {
    disposeLoopsAndConnections();
    return getOrCreate(keriResources, null, null, ON_KERI_NEW, "keri");
  }

  public static KeriResources set(ConnectionProvider provider) {
    return getOrCreate(keriResources, null, provider, ON_KERI_NEW, "keri");
  }

  public static KeriResources set(LoopResources loops) {
    return getOrCreate(keriResources, loops, null, ON_KERI_NEW, "keri");
  }

  KeriResources(LoopResources loops, ConnectionProvider provider) {
    super(loops, provider);
  }

  static final BiFunction<LoopResources, ConnectionProvider, KeriResources> ON_KERI_NEW;

  static final AtomicReference<KeriResources>                          keriResources;

  static {
    ON_KERI_NEW = KeriResources::new;
    keriResources = new AtomicReference<>();
  }

}
